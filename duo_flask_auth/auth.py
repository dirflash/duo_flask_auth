def login(self):
        """
        Handle user login with Duo MFA, rate limiting, and account lockout.

        This function manages the login process, including initial authentication with
        username/password and then redirecting to Duo for MFA if enabled. It also
        handles rate limiting and account lockout.

        Returns:
            Flask response.
        """
        if request.method == "GET":
            return render_template("login_page.html", error=False)

        try:
            username = request.form["username"]
            password = request.form["password"]
            ip_address = request.remote_addr

            current_app.logger.debug(f"Login attempt: {username} from IP: {ip_address}")

            # Check rate limiting for IP address
            if self._is_rate_limited(ip_address, "login"):
                current_app.logger.warning(f"Rate limit exceeded for IP: {ip_address}")
                raise RateLimitedError("Too many login attempts. Please try again later.")

            # Check if database adapter is configured
            if not self.db_adapter:
                current_app.logger.error("Database adapter not configured")
                raise AuthError("Authentication service is not properly configured.")

            # Get user data
            user_data = self.db_adapter.get_user(username)
            current_app.logger.debug(f"User found: {user_data is not None}")

            if not user_data:
                current_app.logger.debug(f"User not found: {username}")

                # Record the login attempt for rate limiting
                self._is_rate_limited(username, "login")  # This increments the counter

                # Log security event
                self.log_security_event(
                    event_type="login_failed",
                    username=username,
                    details={"reason": "User not found"}
                )

                raise InvalidCredentialsError("Invalid username or password")

            # Check if account is locked
            is_locked, lock_reason = self._check_account_lockout(username)
            if is_locked:
                current_app.logger.warning(f"Login attempt for locked account: {username}. Reason: {lock_reason}")

                # Log security event
                self.log_security_event(
                    event_type="login_attempt_locked",
                    username=username,
                    details={"reason": lock_reason}
                )

                raise AccountLockedError(lock_reason or "Account is locked")

            # Create a User object
            user = self.user_factory(user_data)

            # Verify password
            password_check = user.check_password(password)

            if not password_check:
                current_app.logger.debug(f"Password check failed for user: {username}")

                # Increment login attempts counter
                self.db_adapter.increment_login_attempts(username)

                # Log security event
                self.log_security_event(
                    event_type="login_failed",
                    username=username,
                    details={"reason": "Invalid password"}
                )

                # Check account lockout after incrementing attempts
                is_locked, lock_reason = self._check_account_lockout(username)
                if is_locked:
                    current_app.logger.warning(f"Account locked after failed attempt: {username}")

                    # Log security event
                    self.log_security_event(
                        event_type="account_locked",
                        username=username,
                        details={"reason": "Too many failed login attempts"}
                    )

                    raise AccountLockedError(lock_reason or "Account has been locked due to too many failed attempts")

                # Record the failed login attempt for rate limiting
                self._is_rate_limited(username, "login")  # This increments the counter

                raise InvalidCredentialsError("Invalid username or password")

            # Check if the user is active
            if not user.is_active:
                current_app.logger.warning(f"Login attempt for inactive account: {username}")

                # Log security event
                self.log_security_event(
                    event_type="login_inactive",
                    username=username,
                    details={"reason": "Account is inactive"}
                )

                raise AccountLockedError("This account has been deactivated. Please contact an administrator.")

            # Check if password has expired
            if hasattr(user, 'password_expired') and user.password_expired:
                # Set a session flag to force password change
                session["password_expired"] = True
                session["pending_username"] = username

                current_app.logger.info(f"Password expired for user: {username}")

                # Log security event
                self.log_security_event(
                    event_type="password_expired",
                    username=username
                )

                # We'll allow login but redirect to password change page
                login_user(user)
                return redirect(url_for("duo_flask_auth.password_expired"))

            # Password check passed
            # Reset rate limiting
            self._reset_rate_limit(ip_address, "login")
            self._reset_rate_limit(username, "login")

            # Reset login attempts counter and update last login time
            if self.account_lockout_config.get("lockout_reset_on_success", True):
                self.db_adapter.reset_login_attempts(username)

            # Update last login time
            self.db_adapter.update_user(
                username,
                {"last_login": datetime.utcnow()}
            )

            # Log security event
            self.log_security_event(
                event_type="login_success",
                username=username,
                details={"method": "password"}
            )

            # If Duo MFA is enabled for this user and Duo is configured, redirect to Duo
            if user.mfa_enabled and self.duo_client is not None:
                try:
                    # Check if Duo services are available
                    self.duo_client.health_check()

                    # Generate a state parameter to verify the authentication response
                    state = self.duo_client.generate_state()
                    session["duo_state"] = state
                    # Store username in session for completing authentication after Duo callback
                    session["pending_username"] = username

                    # Generate the Duo authentication URL
                    duo_auth_url = self.duo_client.create_auth_url(username, state)

                    # Log security event
                    self.log_security_event(
                        event_type="mfa_initiated",
                        username=username
                    )

                    # Redirect to Duo for 2FA
                    current_app.logger.info(f"Redirecting user {username} to Duo MFA")
                    return redirect(duo_auth_url)

                except DuoException as e:
                    # If there's an issue with Duo, log it and decide how to proceed
                    current_app.logger.error(f"Duo authentication error: {e}")

                    # Log security event
                    self.log_security_event(
                        event_type="mfa_error",
                        username=username,
                        details={"error": str(e)}
                    )

                    # Options:
                    # 1. Fail closed: Deny access and return to login
                    # raise MFARequiredError("MFA service unavailable. Please try again later.")

                    # 2. Fail open: Allow login without MFA (less secure but maintains service availability)
                    current_app.logger.warning(
                        f"Bypassing MFA for {username} due to Duo service unavailable"
                    )
                    login_user(user)
                    return redirect(url_for("duo_flask_auth.login_success"))

            # If MFA is not enabled for this user or Duo is not configured, log in directly
            login_user(user)
            return redirect(url_for("duo_flask_auth.login_success"))

        except (InvalidCredentialsError, AccountLockedError, RateLimitedError, MFARequiredError, AuthError) as e:
            flash(e.message, "error")
            error_code = getattr(e, 'code', None)
            return render_template("login_page.html", error=True, message=e.message, error_code=error_code)

        except Exception as e:
            current_app.logger.error(f"Unexpected error during login: {e}")
            flash("An unexpected error occurred. Please try again later.", "error")
            return render_template("login_page.html", error=True)

    @login_required
    def login_success(self):
        """Handler for successful login - can be overridden by the application."""
        return "Login successful. Override login_success method to customize."

    @login_required
    def password_expired(self):
        """
        Handle password expired scenario.

        This route forces users to change their password if it has expired.

        Returns:
            Flask response.
        """
        if request.method == "GET":
            return render_template("password_expired.html")

        try:
            # Get form data
            current_password = request.form.get("current_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")

            # Validate input
            if not current_password or not new_password or not confirm_password:
                flash("Please fill in all fields.", "error")
                return render_template("password_expired.html")

            if new_password != confirm_password:
                flash("New passwords do not match.", "error")
                return render_template("password_expired.html")

            # Verify current password
            if not current_user.check_password(current_password):
                # Log security event
                self.log_security_event(
                    event_type="password_change_failed",
                    username=current_user.username,
                    details={"reason": "Current password incorrect"}
                )

                flash("Current password is incorrect.", "error")
                return render_template("password_expired.html")

            # Validate new password against policy
            is_valid, reason = self._validate_password(new_password)
            if not is_valid:
                # Log security event
                self.log_security_event(
                    event_type="password_change_failed",
                    username=current_user.username,
                    details={"reason": reason}
                )

                flash(f"Password does not meet requirements: {reason}", "error")
                return render_template("password_expired.html")

            # Check if database adapter is configured
            if not self.db_adapter:
                current_app.logger.error("Database adapter not configured")
                flash("Authentication service is not properly configured.", "error")
                return render_template("password_expired.html")

            # Generate new password hash
            password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")

            # Update the user record
            result = self.db_adapter.update_user(
                current_user.username,
                {
                    "password_hash": password_hash,
                    "last_password_change": datetime.utcnow()
                }
            )

            if result:
                # Clear the expired flag
                session.pop("password_expired", None)

                # Log security event
                self.log_security_event(
                    event_type="password_changed",
                    username=current_user.username,
                    details={"reason": "Password expired"}
                )

                self.logger.info(f"Password changed after expiry for user: {current_user.username}")

                flash("Password has been changed successfully.", "success")
                return redirect(url_for("duo_flask_auth.login_success"))

            else:
                flash("Failed to change password. Please try again.", "error")
                return render_template("password_expired.html")

        except Exception as e:
            self.logger.error(f"Error in password_expired handler: {e}")
            flash("An unexpected error occurred. Please try again.", "error")
            return render_template("password_expired.html")

    @login_required
    def unlock_account(self, username: str):
        """
        Unlock a locked account.

        Args:
            username: The username to unlock

        Returns:
            Flask response.
        """
        # Check if database adapter is configured
        if not self.db_adapter:
            flash("Authentication service is not properly configured.", "error")
            return redirect(url_for("duo_flask_auth.login_success"))

        # Verify admin permissions
        user_data = self.db_adapter.get_user(current_user.username)
        if not user_data or user_data.get("role") != "admin":
            # Log security event
            self.log_security_event(
                event_type="unauthorized_access",
                username=current_user.username,
                details={"action": "unlock_account", "target": username}
            )

            flash("You don't have permission to unlock accounts.", "error")
            return redirect(url_for("duo_flask_auth.login_success"))

        if request.method == "GET":
            # Get the user to unlock
            target_user = self.db_adapter.get_user(username)
            if not target_user:
                flash(f"User '{username}' not found.", "error")
                return redirect(url_for("duo_flask_auth.login_success"))

            return render_template(
                "unlock_account.html",
                user=self.user_factory(target_user),
                cancel_url=url_for("duo_flask_auth.login_success")
            )

        # POST request - unlock the account
        if self._unlock_account(username):
            # Log security event
            self.log_security_event(
                event_type="account_unlocked",
                username=current_user.username,
                details={"target": username}
            )

            flash(f"Account unlocked for user {username}.", "success")
        else:
            flash(f"Failed to unlock account for user {username}.", "error")

        # Redirect to a suitable page (e.g., admin panel)
        return redirect(url_for("duo_flask_auth.login_success"))

    def duo_callback(self):
        """
        Handle the callback from Duo MFA authentication.

        This endpoint receives the response from Duo after a user completes 2FA.
        It validates the state parameter and authentication result before completing login.

        Returns:
            Flask response.
        """
        # Check that we have a pending authentication
        if "duo_state" not in session or "pending_username" not in session:
            current_app.logger.error("Duo callback received without pending authentication")
            return redirect(url_for("duo_flask_auth.login"))

        # Get query parameters
        state = request.args.get("state")
        duo_code = request.args.get("duo_code")

        # Get the pending username
        username = session["pending_username"]

        # Verify state parameter to prevent CSRF
        if state != session["duo_state"]:
            current_app.logger.error("Duo callback state mismatch")

            # Log security event
            self.log_security_event(
                event_type="mfa_failed",
                username=username,
                details={"reason": "State mismatch"}
            )

            return redirect(url_for("duo_flask_auth.login"))

        try:
            # Exchange the code for an authentication result
            decoded_token = self.duo_client.exchange_authorization_code_for_2fa_result(
                duo_code, username
            )

            # Verify successful authentication
            if decoded_token:
                # Load the user and complete login
                user = self.load_user(username)
                if user:
                    login_user(user)

                    # Clean up session
                    session.pop("duo_state", None)
                    session.pop("pending_username", None)

                    # Update last login time
                    if self.db_adapter:
                        self.db_adapter.update_user(
                            username,
                            {"last_login": datetime.utcnow()}
                        )

                    # Log security event
                    self.log_security_event(
                        event_type="login_success",
                        username=username,
                        details={"method": "password_and_mfa"}
                    )

                    current_app.logger.info(
                        f"User {username} successfully authenticated with Duo MFA"
                    )

                    # Check if password has expired
                    if hasattr(user, 'password_expired') and user.password_expired:
                        session["password_expired"] = True
                        return redirect(url_for("duo_flask_auth.password_expired"))

                    return redirect(url_for("duo_flask_auth.login_success"))
                else:
                    current_app.logger.error(f"User {username} not found after Duo authentication")

                    # Log security event
                    self.log_security_event(
                        event_type="mfa_failed",
                        username=username,
                        details={"reason": "User not found after MFA"}
                    )

        except DuoException as e:
            current_app.logger.error(f"Duo authentication error during callback: {e}")

            # Log security event
            self.log_security_event(
                event_type="mfa_failed",
                username=username,
                details={"reason": str(e)}
            )

        # If we get here, something went wrong
        flash("Two-factor authentication failed", "error")
        return redirect(url_for("duo_flask_auth.login"))

    @login_required
    def logout(self):
        """
        Log out the current user.

        Returns:
            Flask response.
        """
        username = current_user.username if current_user.is_authenticated else "Unknown"

        # Log security event
        self.log_security_event(
            event_type="logout",
            username=username
        )

        logout_user()

        # Clear any sensitive session data
        session.pop("duo_state", None)
        session.pop("pending_username", None)
        session.pop("password_expired", None)

        current_app.logger.info(f"User {username} logged out successfully")
        return "You have been logged out."

    @login_required
    def enable_mfa(self):
        """
        Enable MFA for the current user.

        Returns:
            Flask response.
        """
        if request.method == "GET":
            return render_template("enable_mfa.html")

        # Verify that Duo is configured
        if not self.duo_client:
            flash("MFA is not configured for this application.", "error")
            return redirect(url_for("duo_flask_auth.login_success"))

        # Check if database adapter is configured
        if not self.db_adapter:
            flash("Authentication service is not properly configured.", "error")
            return redirect(url_for("duo_flask_auth.login_success"))

        # POST request - enable MFA for the current user
        try:
            # Update the user's MFA status
            result = self.db_adapter.update_user(
                current_user.username,
                {"mfa_enabled": True}
            )

            if result:
                # Log security event
                self.log_security_event(
                    event_type="mfa_enabled",
                    username=current_user.username
                )

                current_app.logger.info(f"MFA enabled for user: {current_user.username}")
                flash("MFA has been enabled for your account.", "success")
            else:
                current_app.logger.error(f"Failed to enable MFA for user: {current_user.username}")
                flash("Failed to enable MFA. Please try again.", "error")

            return redirect(url_for("duo_flask_auth.login_success"))

        except Exception as e:
            current_app.logger.error(f"Error enabling MFA: {e}")
            flash("An error occurred while enabling MFA. Please try again.", "error")
            return redirect(url_for("duo_flask_auth.login_success"))

    @login_required
    def disable_mfa(self):
        """
        Disable MFA for the current user.

        Returns:
            Flask response.
        """
        if request.method == "GET":
            return render_template("disable_mfa.html")

        # Check if database adapter is configured
        if not self.db_adapter:
            flash("Authentication service is not properly configured.", "error")
            return redirect(url_for("duo_flask_auth.login_success"))

        # POST request - disable MFA for the current user
        try:
            # Update the user's MFA status
            result = self.db_adapter.update_user(
                current_user.username,
                {"mfa_enabled": False}
            )

            if result:
                # Log security event
                self.log_security_event(
                    event_type="mfa_disabled",
                    username=current_user.username
                )

                current_app.logger.info(f"MFA disabled for user: {current_user.username}")
                flash("MFA has been disabled for your account.", "success")
            else:
                current_app.logger.error(f"Failed to disable MFA for user: {current_user.username}")
                flash("Failed to disable MFA. Please try again.", "error")

            return redirect(url_for("duo_flask_auth.login_success"))

        except Exception as e:
            current_app.logger.error(f"Error disabling MFA: {e}")
            flash("An error occurred while disabling MFA. Please try again.", "error")
            return redirect(url_for("duo_flask_auth.login_success"))

    def verify_email(self, username: str) -> bool:
        """
        Mark a user's email as verified.

        Args:
            username: The username (email) to verify

        Returns:
            True if successful, False otherwise
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return False

        try:
            result = self.db_adapter.update_user(
                username,
                {"email_verified": True}
            )

            if result:
                # Log security event
                self.log_security_event(
                    event_type="email_verified",
                    username=username,
                    details={"verified_by": getattr(current_user, 'username', 'system')}
                )

            self.logger.info(f"Email verified for user: {username}")
            return result

        except Exception as e:
            self.logger.error(f"Error verifying email for user '{username}': {e}")
            return False

    def update_user_role(self, username: str, role: str) -> bool:
        """
        Update a user's role.

        Args:
            username: The username to update
            role: The new role to assign

        Returns:
            True if successful, False otherwise
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return False

        try:
            # Verify that the role is valid
            valid_roles = ["user", "admin", "manager"]
            if role not in valid_roles:
                self.logger.warning(f"Invalid role '{role}' specified for user '{username}'")
                return False

            result = self.db_adapter.update_user(
                username,
                {"role": role}
            )

            if result:
                # Log security event
                self.log_security_event(
                    event_type="role_updated",
                    username=username,
                    details={
                        "new_role": role,
                        "updated_by": getattr(current_user, 'username', 'system')
                    }
                )

            self.logger.info(f"Role updated for user '{username}' to '{role}'")
            return result

        except Exception as e:
            self.logger.error(f"Error updating role for user '{username}': {e}")
            return False

    def set_user_active_status(self, username: str, is_active: bool) -> bool:
        """
        Set a user's active status.

        Args:
            username: The username to update
            is_active: Whether the user should be active

        Returns:
            True if successful, False otherwise
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return False

        try:
            update_data = {"is_active": is_active}

            # If activating, also clear lockout
            if is_active:
                update_data.update({
                    "login_attempts": 0,
                    "locked_until": None
                })

            result = self.db_adapter.update_user(
                username,
                update_data
            )

            if result:
                # Log security event
                status_str = "activated" if is_active else "deactivated"
                self.log_security_event(
                    event_type=f"account_{status_str}",
                    username=username,
                    details={
                        "updated_by": getattr(current_user, 'username', 'system')
                    }
                )

            status_str = "activated" if is_active else "deactivated"
            self.logger.info(f"User '{username}' {status_str}")
            return result

        except Exception as e:
            self.logger.error(f"Error updating active status for user '{username}': {e}")
            return False

    def forgot_password(self):
        """
        Handle forgot password requests.

        Returns:
            Flask response.
        """
        if request.method == "GET":
            return render_template("forgot_password.html")

        # Process the form submission
        username = request.form.get("username")
        if not username:
            flash("Please enter your email address.", "error")
            return render_template("forgot_password.html")

        # Check rate limiting for password resets
        ip_address = request.remote_addr
        if self._is_rate_limited(ip_address, "password_reset"):
            self.logger.warning(f"Rate limit exceeded for password resets from IP: {ip_address}")

            # Log security event
            self.log_security_event(
                event_type="password_reset_rate_limited",
                username=username,
                details={"ip_address": ip_address}
            )

            flash("Too many password reset attempts. Please try again later.", "error")
            return redirect(url_for("duo_flask_auth.login"))

        # For GET requests, show the reset form
        if request.method == "GET":
            # Verify that the token is valid
            user_data = self.db_adapter.get_user_by_reset_token(token)
            if not user_data or user_data.get("username") != username:
                flash("Invalid or expired password reset link.", "error")
                return redirect(url_for("duo_flask_auth.login"))

            return render_template(
                "reset_password.html",
                username=username,
                token=token,
                require_special=self.password_policy.get("require_special", False)
            )

        # Process the form submission
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Validate passwords
        if not new_password or not confirm_password:
            flash("Please fill in all fields.", "error")
            return render_template(
                "reset_password.html",
                username=username,
                token=token,
                require_special=self.password_policy.get("require_special", False)
            )

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template(
                "reset_password.html",
                username=username,
                token=token,
                require_special=self.password_policy.get("require_special", False)
            )

        # Validate password against policy
        is_valid, reason = self._validate_password(new_password)
        if not is_valid:
            flash(f"Password does not meet requirements: {reason}", "error")
            return render_template(
                "reset_password.html",
                username=username,
                token=token,
                require_special=self.password_policy.get("require_special", False)
            )

        # Reset the password
        password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")

        # Get user by token
        user_data = self.db_adapter.get_user_by_reset_token(token)
        if not user_data or user_data.get("username") != username:
            # Log security event
            self.log_security_event(
                event_type="password_reset_failed",
                username=username,
                details={"reason": "Invalid or expired token"}
            )

            flash("Invalid or expired password reset link.", "error")
            return redirect(url_for("duo_flask_auth.login"))

        # Update the user record
        result = self.db_adapter.update_user(
            username,
            {
                "password_hash": password_hash,
                "last_password_change": datetime.utcnow(),
                "reset_token": None,
                "reset_token_expires": None,
                "login_attempts": 0  # Reset login attempts
            }
        )

        if result:
            # Reset rate limiting
            self._reset_rate_limit(ip_address, "password_reset")

            # Log security event
            self.log_security_event(
                event_type="password_reset_successful",
                username=username
            )

            flash("Password has been reset successfully. You can now log in with your new password.", "success")
            return redirect(url_for("duo_flask_auth.login"))
        else:
            # Log security event
            self.log_security_event(
                event_type="password_reset_failed",
                username=username,
                details={"reason": "Database update failed"}
            )

            flash("Failed to reset password. Please try again.", "error")
            return render_template(
                "reset_password.html",
                username=username,
                token=token,
                require_special=self.password_policy.get("require_special", False)
            )

    def reset_password_with_token(self, username: str, token: str, new_password: str) -> bool:
        """
        Reset a user's password using a reset token.

        Args:
            username: The username to reset password for
            token: The reset token
            new_password: The new password

        Returns:
            True if successful, False otherwise
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return False

        try:
            # Check rate limiting for password resets
            ip_address = request.remote_addr if request else None
            if ip_address and self._is_rate_limited(ip_address, "password_reset"):
                self.logger.warning(f"Rate limit exceeded for password resets from IP: {ip_address}")
                return False

            # Get the user by token
            user_data = self.db_adapter.get_user_by_reset_token(token)
            if not user_data or user_data.get("username") != username:
                self.logger.warning(f"Invalid or expired token for user: {username}")
                return False

            # Validate the new password
            is_valid, reason = self._validate_password(new_password)
            if not is_valid:
                self.logger.warning(f"Invalid password during reset: {reason}")
                return False

            # Generate new password hash
            password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")

            # Update user record
            result = self.db_adapter.update_user(
                username,
                {
                    "password_hash": password_hash,
                    "last_password_change": datetime.utcnow(),
                    "reset_token": None,
                    "reset_token_expires": None,
                    "login_attempts": 0  # Reset login attempts
                }
            )

            if result and ip_address:
                # Reset rate limiting
                self._reset_rate_limit(ip_address, "password_reset")

            return result

        except Exception as e:
            self.logger.error(f"Error resetting password for user '{username}': {e}")
            return False

    @login_required
    def add_user(self, username: str, password: str) -> str:
        """
        Add a user to the database with enhanced security validation.

        Args:
            username: The username (email) of the user to be added
            password: The password of the user to be added

        Returns:
            A message indicating whether the user was added successfully or not
        """
        try:
            # SECURITY CHECK 1: Double-check authentication (defense in depth)
            if not current_user.is_authenticated:
                self.logger.error(
                    f"Unauthenticated access attempt to add_user from IP: {request.remote_addr}"
                )

                # Log security event
                self.log_security_event(
                    event_type="unauthorized_access",
                    username="unknown",
                    details={"action": "add_user", "target": username}
                )

                return "Error: Authentication required."

            # Check if database adapter is configured
            if not self.db_adapter:
                self.logger.error("Database adapter not configured")
                return "Error: Authentication service is not properly configured."

            # Get current user data
            current_user_data = self.db_adapter.get_user(current_user.username)

            # SECURITY CHECK 2: Admin role validation
            if not current_user_data or current_user_data.get("role") != "admin":
                self.logger.warning(
                    f"Non-admin user {current_user.username} attempted to add user"
                )

                # Log security event
                self.log_security_event(
                    event_type="unauthorized_access",
                    username=current_user.username,
                    details={"action": "add_user", "target": username}
                )

                return "Error: Admin privileges required to add users."

            self.logger.info(f"Adding user attempt: {username}")
            self.logger.info(f"Request made by admin: {current_user.username}")

            # Regular validation continues...
            # VALIDATION 1: Input validation with length restrictions
            if not username or not password:
                self.logger.warning("Missing username or password")
                return "Error: Username and password are required."

            # Prevent excessively long inputs
            if len(username) > 100 or len(password) > 72:  # bcrypt max is 72 bytes
                self.logger.warning("Username or password exceeds maximum length")
                return "Error: Username or password too long."

            # VALIDATION 2: Email format validation
            if not self.is_valid_email(username):
                self.logger.warning(f"Invalid email format: {username}")
                return f"Error: '{username}' is not a valid email address."

            # VALIDATION 3: Password strength validation
            is_valid, reason = self._validate_password(password)
            if not is_valid:
                self.logger.warning(f"Password validation failed: {reason}")
                return f"Error: {reason}"

            # VALIDATION 4: Check if user already exists
            existing_user = self.db_adapter.get_user(username)
            if existing_user:
                self.logger.warning(f"User '{username}' already exists in the database")
                return f"Error: User '{username}' already exists in the database."

            # All validations passed, proceed with user creation
            password_hash = generate_password_hash(password, method="pbkdf2:sha256")

            # Current time
            current_time = datetime.utcnow()

            # Add user with full schema implementation
            user_data = {
                "username": username,
                "password_hash": password_hash,
                "created_by": current_user.username,
                "created_at": current_time,
                "is_active": True,
                "role": "user",  # Default role
                "last_password_change": current_time,
                "account_id": str(uuid.uuid4()),
                "login_attempts": 0,
                "creation_ip": request.remote_addr,
                "mfa_enabled": False,  # Default to MFA disabled
                "last_login": None,
                "email_verified": False,
                "reset_token": None,
                "reset_token_expires": None,
                "locked_until": None
            }

            # Create the user
            success, result = self.db_adapter.create_user(user_data)

            if success:
                # Log security event
                self.log_security_event(
                    event_type="user_created",
                    username=current_user.username,
                    details={"new_user": username}
                )

                self.logger.info(f"User '{username}' added successfully with ID: {result}")
                return f"Success: User '{username}' added successfully."
            else:
                self.logger.error(f"Failed to add user '{username}': {result}")
                return f"Error: Failed to add user '{username}'. {result}"

        except Exception as e:
            self.logger.error(f"Error adding user '{username}': {e}")
            return f"Error: Failed to add user '{username}'. {str(e)}"

    def log_security_event(self, event_type: str, username: str,
                        ip_address: Optional[str] = None,
                        details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Log a security-related event.

        Args:
            event_type: Type of event (login, logout, password_change, etc.)
            username: Username associated with the event
            ip_address: IP address from which the event originated
            details: Additional details about the event

        Returns:
            True if logged successfully, False otherwise
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return False

        try:
            # Use the request IP address if none provided
            if ip_address is None and request:
                ip_address = request.remote_addr

            # Use empty dict if no details provided
            if details is None:
                details = {}

            # Create event data
            event_data = {
                "timestamp": datetime.utcnow(),
                "event_type": event_type,
                "username": username,
                "ip_address": ip_address,
                "user_agent": request.user_agent.string if request and hasattr(request, 'user_agent') else None,
                "details": details
            }

            # Log the event
            return self.db_adapter.log_security_event(event_data)

        except Exception as e:
            self.logger.error(f"Error logging security event: {e}")
            return False

    def get_security_events(self,
                          filters: Optional[Dict[str, Any]] = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get security events.

        Args:
            filters: Optional filters to apply
            limit: Maximum number of events to return

        Returns:
            List of security events
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return []

        try:
            return self.db_adapter.get_security_events(filters, limit)

        except Exception as e:
            self.logger.error(f"Error retrieving security events: {e}")
            return [] "password_reset"):
            self.logger.warning(f"Rate limit exceeded for password resets from IP: {ip_address}")

            # Log security event
            self.log_security_event(
                event_type="password_reset_rate_limited",
                username=username,
                details={"ip_address": ip_address}
            )

            flash("Too many password reset attempts. Please try again later.", "error")
            return render_template("forgot_password.html")

        # Check if database adapter is configured
        if not self.db_adapter:
            flash("Authentication service is not properly configured.", "error")
            return render_template("forgot_password.html")

        # Check if user exists
        user_data = self.db_adapter.get_user(username)
        if not user_data:
            # Don't reveal that the user doesn't exist for security reasons
            flash("If an account exists with that email, a password reset link has been sent.", "success")
            return render_template("forgot_password.html")

        # Check if user is active
        if not user_data.get("is_active", True):
            # Don't reveal that the account is inactive for security reasons
            flash("If an account exists with that email, a password reset link has been sent.", "success")

            # Log security event
            self.log_security_event(
                event_type="password_reset_inactive",
                username=username
            )

            return render_template("forgot_password.html")

        # Generate a password reset token
        token = self.generate_password_reset_token(username)

        if token:
            # In a real application, you would send this token to the user's email
            # For this example, we'll just display it
            reset_url = url_for('duo_flask_auth.reset_password', username=username, token=token, _external=True)

            # Log security event
            self.log_security_event(
                event_type="password_reset_requested",
                username=username
            )

            flash("Password reset link has been sent to your email address.", "success")

            # In development mode, show the link directly
            if current_app.debug:
                flash(f"Reset link: {reset_url}", "info")

            return render_template("forgot_password.html", reset_link=reset_url)
        else:
            flash("Failed to generate password reset token. Please try again.", "error")
            return render_template("forgot_password.html")

    def generate_password_reset_token(self, username: str, expiry_hours: int = 24) -> Optional[str]:
        """
        Generate a password reset token for a user.

        Args:
            username: The username to generate a token for
            expiry_hours: Number of hours until the token expires

        Returns:
            The reset token, or None if generation failed
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return None

        try:
            # Check rate limiting for password resets
            ip_address = request.remote_addr if request else None
            if ip_address and self._is_rate_limited(ip_address, "password_reset"):
                self.logger.warning(f"Rate limit exceeded for password resets from IP: {ip_address}")
                return None

            # Get the user
            user_data = self.db_adapter.get_user(username)
            if not user_data:
                self.logger.warning(f"Password reset requested for non-existent user: {username}")
                return None

            if not user_data.get("is_active", True):
                self.logger.warning(f"Password reset requested for inactive user: {username}")
                return None

            # Generate a secure random token
            reset_token = str(uuid.uuid4())

            # Calculate expiry time
            expiry_time = datetime.utcnow() + timedelta(hours=expiry_hours)

            # Update the user record
            result = self.db_adapter.update_user(
                username,
                {
                    "reset_token": reset_token,
                    "reset_token_expires": expiry_time
                }
            )

            if result:
                self.logger.info(f"Password reset token generated for user: {username}")
                return reset_token
            else:
                self.logger.error(f"Failed to generate password reset token for user: {username}")
                return None

        except Exception as e:
            self.logger.error(f"Error generating password reset token for user '{username}': {e}")
            return None

    def reset_password(self, username: str, token: str):
        """
        Handle password reset with token.

        Args:
            username: The username to reset password for
            token: The reset token

        Returns:
            Flask response.
        """
        # Check if database adapter is configured
        if not self.db_adapter:
            flash("Authentication service is not properly configured.", "error")
            return redirect(url_for("duo_flask_auth.login"))

        # Check rate limiting for password resets
        ip_address = request.remote_addr
        if self._is_rate_limited(ip_address,"""
Main class for the Duo Flask Auth library with flexibility enhancements.

This module provides the DuoFlaskAuth class, which handles authentication,
Duo MFA integration, and security features with support for different
database backends and customizable routes.
"""

import logging
import re
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable, Type, Union

import certifi

# Import Duo Universal SDK
from duo_universal.client import Client, DuoException
from flask import Blueprint, Flask, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from .db_adapters import DatabaseAdapter, get_db_adapter
from .user_model import BaseUser, get_user_factory
from .exceptions import (
    AuthError,
    InvalidCredentialsError,
    AccountLockedError,
    MFARequiredError,
    RateLimitedError,
    PasswordPolicyError,
    TokenInvalidError,
    PermissionDeniedError
)


class DuoFlaskAuth:
    """
    Flask authentication library with Duo MFA support and enhanced flexibility.

    This class provides authentication functionality with optional Duo MFA integration
    for Flask applications, with support for different database backends,
    customizable routes, and user models.
    """

    def __init__(
        self,
        app: Optional[Flask] = None,
        db_config: Optional[Dict[str, Any]] = None,
        db_adapter: Optional[Union[str, DatabaseAdapter]] = None,
        duo_config: Optional[Dict[str, Any]] = None,
        template_folder: str = 'templates',
        routes_prefix: str = '/auth',
        user_model: str = 'default',
        rate_limit_config: Optional[Dict[str, Any]] = None,
        account_lockout_config: Optional[Dict[str, Any]] = None,
        password_policy: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the DuoFlaskAuth extension.

        Args:
            app: The Flask application to initialize with.
            db_config: Database connection configuration.
            db_adapter: Database adapter type ('mongodb', 'sqlalchemy') or instance.
            duo_config: Duo MFA configuration.
            template_folder: Folder for auth templates.
            routes_prefix: Prefix for authentication routes.
            user_model: User model type.
            rate_limit_config: Configuration for rate limiting.
            account_lockout_config: Configuration for account lockout.
            password_policy: Configuration for password policies.
        """
        self.login_manager = LoginManager()
        self.db_config = db_config or {}
        self.duo_config = duo_config or {}
        self.template_folder = template_folder
        self.routes_prefix = routes_prefix
        self.user_model = user_model
        self.duo_client = None
        self.csrf = CSRFProtect()

        # Initialize database adapter
        if isinstance(db_adapter, DatabaseAdapter):
            self.db_adapter = db_adapter
        elif isinstance(db_adapter, str):
            self.db_adapter = get_db_adapter(db_adapter, self.db_config)
        elif db_config:
            # Default to MongoDB if not specified but config is provided
            self.db_adapter = get_db_adapter('mongodb', self.db_config)
        else:
            self.db_adapter = None

        # Get user factory
        self.user_factory = get_user_factory(user_model)

        # Create blueprint with specified route prefix
        self.blueprint = Blueprint('duo_flask_auth', __name__,
                                  url_prefix=routes_prefix,
                                  template_folder=template_folder)

        # Rate limiting configuration
        self.rate_limit_config = rate_limit_config or {
            "enabled": True,
            "max_attempts": {
                "login": 5,       # 5 attempts
                "password_reset": 3  # 3 attempts
            },
            "window_seconds": {
                "login": 300,        # 5 minutes
                "password_reset": 600   # 10 minutes
            }
        }

        # Account lockout configuration
        self.account_lockout_config = account_lockout_config or {
            "enabled": True,
            "max_attempts": 5,      # Lock after 5 failed attempts
            "lockout_duration": 1800,  # 30 minutes
            "lockout_reset_on_success": True
        }

        # Password policy configuration
        self.password_policy = password_policy or {
            "min_length": 8,
            "require_upper": True,
            "require_lower": True,
            "require_digit": True,
            "require_special": False,
            "max_age_days": 90,   # Maximum password age
            "prevent_common": True,  # Prevent common passwords
            "common_passwords": ["Password123", "Admin123", "Welcome123"]  # Example list
        }

        # Set up in-memory rate limiting storage
        # In a production environment, this should be replaced with Redis or similar
        self._rate_limit_store = {}

        # Configure logger
        self.logger = logging.getLogger("duo_flask_auth")
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self._setup_routes()

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize the extension with the given Flask application.

        Args:
            app: The Flask application to initialize with.

        Raises:
            ValueError: If required configuration is missing.
        """
        # Validate configuration
        if self.db_adapter is None and not self.db_config:
            self.logger.warning("No database configuration provided - some features will be unavailable")

        # Validate Duo configuration if provided
        if self.duo_config:
            required_duo_keys = ['client_id', 'client_secret', 'api_host', 'redirect_uri']
            for key in required_duo_keys:
                if key not in self.duo_config:
                    raise ValueError(f"Missing required Duo configuration key: {key}")

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['duo_flask_auth'] = self

        # Set up CSRF protection
        self.csrf.init_app(app)

        # Set up the login manager
        self.login_manager.init_app(app)
        self.login_manager.login_view = "duo_flask_auth.login"
        self.login_manager.login_message = "Please log in to access this page."
        self.login_manager.login_message_category = "info"

        # Set up the database adapter if provided
        if self.db_adapter:
            self.db_adapter.initialize(app)

        # Set up the Duo client if provided
        if self.duo_config:
            self._setup_duo_client(app)

        # Register the user loader
        @self.login_manager.user_loader
        def load_user(user_id):
            return self.load_user(user_id)

        # Register the blueprint with the app
        app.register_blueprint(self.blueprint)

        self.logger.info(f"DuoFlaskAuth initialized with routes at {self.routes_prefix}")

    def _setup_duo_client(self, app: Flask) -> None:
        """
        Set up Duo MFA client.

        Args:
            app: The Flask application.
        """
        # Extract Duo configuration
        client_id = self.duo_config.get('client_id')
        client_secret = self.duo_config.get('client_secret')
        api_host = self.duo_config.get('api_host')
        redirect_uri = self.duo_config.get('redirect_uri')

        # Initialize Duo client if all required parameters are provided
        if all([client_id, client_secret, api_host, redirect_uri]):
            try:
                self.duo_client = Client(
                    client_id=client_id,
                    client_secret=client_secret,
                    host=api_host,
                    redirect_uri=redirect_uri,
                )
                app.logger.info("Duo MFA client initialized")
            except ImportError:
                app.logger.error("Failed to import Duo Universal SDK. Install it with: pip install duo-universal")
            except Exception as e:
                app.logger.error(f"Error initializing Duo client: {e}")
        else:
            app.logger.warning(
                "Duo MFA not fully configured. Some parameters are missing."
            )

    def _setup_routes(self) -> None:
        """Set up authentication routes on the blueprint."""
        self.blueprint.route('/login/', methods=['GET', 'POST'])(self.login)
        self.blueprint.route('/duo-callback')(self.duo_callback)
        self.blueprint.route('/logout')(self.logout)
        self.blueprint.route('/enable-mfa', methods=['GET', 'POST'])(self.enable_mfa)
        self.blueprint.route('/disable-mfa', methods=['GET', 'POST'])(self.disable_mfa)
        self.blueprint.route('/add-user/<username>/<password>', methods=['GET', 'POST'])(self.add_user)
        self.blueprint.route('/unlock-account/<username>', methods=['GET', 'POST'])(self.unlock_account)
        self.blueprint.route('/password-expired', methods=['GET', 'POST'])(self.password_expired)
        self.blueprint.route('/forgot-password', methods=['GET', 'POST'])(self.forgot_password)
        self.blueprint.route('/reset-password/<username>/<token>', methods=['GET', 'POST'])(self.reset_password)
        self.blueprint.route('/login-success')(self.login_success)

    def load_user(self, user_id: str) -> Optional[BaseUser]:
        """
        Load a user from the database by their user ID.

        Args:
            user_id: The ID of the user to load (typically the username).

        Returns:
            A User object if the user is found in the database, otherwise None.
        """
        current_app.logger.debug(f"Loading user: {user_id}")

        if not self.db_adapter:
            current_app.logger.error("Database adapter not configured")
            return None

        # Get user data from the database
        user_data = self.db_adapter.get_user(user_id)

        if not user_data:
            return None

        # Check if password has expired
        if self._is_password_expired(user_data):
            user_data['password_expired'] = True

        # Create a User object with the data from the database
        try:
            user = self.user_factory(user_data)
            return user
        except Exception as e:
            current_app.logger.error(f"Error creating user object: {e}")
            return None

    def is_valid_email(self, email: str) -> bool:
        """
        Validate email format using regex.

        Args:
            email: The email to validate

        Returns:
            True if valid email format, False otherwise
        """
        # Basic email validation pattern
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    def _is_rate_limited(self, key: str, action: str) -> bool:
        """
        Check if an action from a key (IP or username) is rate limited.

        Args:
            key: The key to check (IP address or username)
            action: The action to check (login, password_reset, etc.)

        Returns:
            True if rate limited, False otherwise
        """
        if not self.rate_limit_config.get("enabled", True):
            return False

        # Get the maximum attempts and window for this action
        max_attempts = self.rate_limit_config.get("max_attempts", {}).get(action, 5)
        window_seconds = self.rate_limit_config.get("window_seconds", {}).get(action, 300)

        # Create a composite key
        cache_key = f"{key}:{action}"

        # Get the current time
        now = time.time()

        # Check if the key exists in the store
        if cache_key not in self._rate_limit_store:
            # If not, create a new entry
            self._rate_limit_store[cache_key] = {
                "attempts": 1,
                "first_attempt": now,
                "last_attempt": now
            }
            return False

        # Get the entry
        entry = self._rate_limit_store[cache_key]

        # Check if the entry has expired
        if now - entry["first_attempt"] > window_seconds:
            # If so, reset it
            entry["attempts"] = 1
            entry["first_attempt"] = now
            entry["last_attempt"] = now
            return False

        # Update the last attempt time
        entry["last_attempt"] = now

        # Increment the attempt counter
        entry["attempts"] += 1

        # Check if the maximum attempts have been exceeded
        return entry["attempts"] > max_attempts

    def _reset_rate_limit(self, key: str, action: str) -> None:
        """
        Reset the rate limit for a key and action.

        Args:
            key: The key to reset (IP address or username)
            action: The action to reset (login, password_reset, etc.)
        """
        cache_key = f"{key}:{action}"
        if cache_key in self._rate_limit_store:
            del self._rate_limit_store[cache_key]

    def _check_account_lockout(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an account is locked.

        Args:
            username: The username to check

        Returns:
            Tuple containing:
              - Boolean indicating if the account is locked
              - Optional reason for lockout
        """
        if not self.account_lockout_config.get("enabled", True) or not self.db_adapter:
            return False, None

        # Get user data
        user_data = self.db_adapter.get_user(username)

        if not user_data:
            return False, None

        # Check if account is explicitly inactive
        if not user_data.get("is_active", True):
            return True, "Account is deactivated"

        # Check if there's a lockout timestamp and it's in the future
        locked_until = user_data.get("locked_until")
        if locked_until and isinstance(locked_until, datetime) and locked_until > datetime.utcnow():
            return True, f"Account is locked until {locked_until}"

        # Check if too many failed attempts
        login_attempts = user_data.get("login_attempts", 0)
        max_attempts = self.account_lockout_config.get("max_attempts", 5)

        if login_attempts >= max_attempts:
            # Lock the account
            lockout_duration = self.account_lockout_config.get("lockout_duration", 1800)  # 30 minutes
            locked_until = datetime.utcnow() + timedelta(seconds=lockout_duration)

            # Update the user record
            self.db_adapter.update_user(
                username,
                {"locked_until": locked_until}
            )

            return True, f"Account is locked until {locked_until}"

        return False, None

    def _unlock_account(self, username: str) -> bool:
        """
        Unlock an account.

        Args:
            username: The username to unlock

        Returns:
            True if successful, False otherwise
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return False

        try:
            # Reset login attempts and clear lockout
            result = self.db_adapter.update_user(
                username,
                {
                    "login_attempts": 0,
                    "locked_until": None
                }
            )

            self.logger.info(f"Account unlocked for user: {username}")
            return result

        except Exception as e:
            self.logger.error(f"Error unlocking account for user '{username}': {e}")
            return False

    def _is_password_expired(self, user_data: Dict[str, Any]) -> bool:
        """
        Check if a user's password has expired.

        Args:
            user_data: The user data from the database

        Returns:
            True if the password has expired, False otherwise
        """
        # Check if password expiration is enabled
        max_age_days = self.password_policy.get("max_age_days")
        if not max_age_days:
            return False

        # Check if there's a last password change timestamp
        last_password_change = user_data.get("last_password_change")
        if not last_password_change or not isinstance(last_password_change, datetime):
            return False

        # Check if the password is older than the maximum age
        password_age = (datetime.utcnow() - last_password_change).days
        return password_age > max_age_days

    def _validate_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a password against the password policy.

        Args:
            password: The password to validate

        Returns:
            Tuple containing:
              - Boolean indicating if the password is valid
              - Optional reason why the password is invalid
        """
        # Check length
        min_length = self.password_policy.get("min_length", 8)
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters long"

        # Check for uppercase letters
        if self.password_policy.get("require_upper", True) and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        # Check for lowercase letters
        if self.password_policy.get("require_lower", True) and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        # Check for digits
        if self.password_policy.get("require_digit", True) and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"

        # Check for special characters
        if self.password_policy.get("require_special", False) and not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password):
            return False, "Password must contain at least one special character"

        # Check for common passwords
        if self.password_policy.get("prevent_common", True):
            common_passwords = self.password_policy.get("common_passwords", [])
            if password in common_passwords:
                return False, "Password is too common"

        return True, None