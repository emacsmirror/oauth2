;;; oauth2.el --- OAuth 2.0 Authorization Protocol  -*- lexical-binding:t -*-

;; Copyright (C) 2011-2021 Free Software Foundation, Inc

;; Author: Julien Danjou <julien@danjou.info>
;; Maintainer: emacs-devel@gnu.org
;; Version: 0.17
;; URL: https://elpa.gnu.org/packages/oauth2.html
;; Keywords: comm
;; Package-Requires: ((emacs "27.1"))

;; This file is part of GNU Emacs.

;; GNU Emacs is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; GNU Emacs is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Implementation of the OAuth 2.0 draft.
;;
;; The main entry point is `oauth2-auth-and-store' which will return a token
;; structure, which contains information needed for OAuth2 authentication,
;; e.g. access_token, refresh_token, etc.
;;
;; If the token needs to be refreshed, call `oauth2-refresh-access' on the token
;; and it will be refreshed with a new access_token.  The code will also store
;; the new value of the access token for reuse.

;;; Code:

(eval-when-compile (require 'cl-lib))
(require 'plstore)
(require 'json)
(require 'url-http)

(defvar url-http-data)
(defvar url-http-method)
(defvar url-http-extra-headers)
(defvar url-callback-arguments)
(defvar url-callback-function)

(defgroup oauth2 nil
  "OAuth 2.0 Authorization Protocol."
  :group 'comm
  :link '(url-link :tag "Savannah"
                   "https://git.savannah.gnu.org/cgit/emacs/elpa.git/tree/?h=externals/oauth2")
  :link '(url-link :tag "ELPA" "https://elpa.gnu.org/packages/oauth2.html"))

(defcustom oauth2-token-file (locate-user-emacs-file "oauth2.plstore")
  "File path where store OAuth tokens."
  :group 'oauth2
  :type 'file)

(defvar oauth2-debug nil
  "Enable verbose logging in oauth2 to help debugging.")

(defvar oauth2--url-advice nil)
(defvar oauth2--token-data)

(defun oauth2--do-warn (&rest msg)
  "Actual function to log MSG based on how `oauth2-debug' is set."
  (setcar msg (concat "[oauth2] " (car msg)))
  (apply (if (functionp oauth2-debug)
             oauth2-debug
           'message)
         msg))

(defun oauth2--do-trivia (&rest msg)
  "Output debug message when `oauth2-debug' is set to \\='trivia."
  (when (or (eq oauth2-debug 'trivia)
            (functionp oauth2-debug))
    (apply #'oauth2--do-warn msg)))

(defun oauth2--do-debug (&rest msg)
  "Output debug messages when `oauth2-debug' is enabled."
  (when oauth2-debug
    (apply #'oauth2--do-warn msg)))

(defmacro oauth2--with-plstore (&rest body)
  "A macro that ensures the plstore is closed after use."
  `(let ((plstore (plstore-open oauth2-token-file)))
     (unwind-protect
         (progn ,@body)
       (plstore-close plstore))))

(defun oauth2--current-timestamp ()
  "Get the current timestamp in seconds."
  (time-convert nil 'integer))

(defun oauth2--update-plstore (plstore token)
  "Update the file storage with handle PLSTORE with the value in TOKEN."
  (plstore-put plstore (oauth2-token-plstore-id token)
               nil `(:access-token
                     ,(oauth2-token-access-token token)
                     :refresh-token
                     ,(oauth2-token-refresh-token token)
                     :request-timestamp
                     ,(oauth2-token-request-timestamp token)
                     :access-response
                     ,(oauth2-token-access-response token)))
  (plstore-save plstore))

(defun oauth2-request-authorization (auth-url client-id &optional scope state
                                              redirect-uri)
  "Request OAuth authorization at AUTH-URL by launching `browse-url'.
CLIENT-ID is the client id provided by the provider which uses
REDIRECT-URI when requesting an access-token.  The default redirect_uri
for desktop application is usually \"urn:ietf:wg:oauth:2.0:oob\".  SCOPE
identifies the resources that your application can access on the user's
behalf.  STATE is a string that your application uses to maintain the
state between the request and redirect response.

Returns the code provided by the service."
  (let ((url (concat auth-url
                     (if (string-match-p "\?" auth-url) "&" "?")
                     "client_id=" (url-hexify-string client-id)
                     "&response_type=code"
                     "&redirect_uri=" (url-hexify-string
                                       (or redirect-uri
                                           "urn:ietf:wg:oauth:2.0:oob"))
                     (if scope (concat "&scope=" (url-hexify-string scope)) "")
                     (if state (concat "&state=" (url-hexify-string state)) "")
                     ;; The following two parameters are required for Gmail
                     ;; OAuth2 to generate the refresh token
                     "&access_type=offline"
                     "&prompt=consent")))
    (browse-url url)
    (read-string (concat "Follow the instruction on your default browser, or "
                         "visit:\n" url
                         "\nEnter the code your browser displayed: "))))

(defun oauth2-request-access-parse ()
  "Parse the result of an OAuth request."
  (goto-char (point-min))
  (when (search-forward-regexp "^$" nil t)
    (json-read)))

(defun oauth2-make-access-request (url data)
  "Make an access request to URL using DATA in POST requests."
  (let ((func-name (nth 1 (backtrace-frame 2))))
    (oauth2--do-trivia "%s: url: %s" func-name url)
    (oauth2--do-trivia "%s: data: %s" func-name data)
    (let ((url-request-method "POST")
          (url-request-data data)
          (url-request-extra-headers
           '(("Content-Type" . "application/x-www-form-urlencoded"))))
      (with-current-buffer (url-retrieve-synchronously url)
        (let ((data (oauth2-request-access-parse)))
          (kill-buffer (current-buffer))
          (oauth2--do-trivia "%s: response: %s" func-name
                             (prin1-to-string data))
          data)))))

(cl-defstruct oauth2-token
  plstore
  plstore-id
  client-id
  client-secret
  access-token
  refresh-token
  request-timestamp
  auth-url
  token-url
  access-response)

(defun oauth2-request-access (auth-url token-url client-id client-secret code
                                       &optional redirect-uri)
  "Request OAuth access.
TOKEN-URL is the URL for making the request.  CLIENT-ID and
CLIENT-SECRET are provided by the service provider.  The CODE should be
obtained with `oauth2-request-authorization'.  REDIRECT-URI is used when
requesting access-token.  The default value for desktop application is
usually \"urn:ietf:wg:oauth:2.0:oob\".

Returns an `oauth2-token'."
  (when code
    (let ((request-timestamp (oauth2--current-timestamp))
          (result
           (oauth2-make-access-request
            token-url
            (url-encode-url
             (concat
              "client_id=" client-id
              (when client-secret
                (concat  "&client_secret=" client-secret))
              "&code=" code
              "&redirect_uri=" (or redirect-uri "urn:ietf:wg:oauth:2.0:oob")
              "&grant_type=authorization_code")))))
      (make-oauth2-token :client-id client-id
                         :client-secret client-secret
                         :access-token (cdr (assoc 'access_token result))
                         :refresh-token (cdr (assoc 'refresh_token result))
                         :request-timestamp request-timestamp
                         :auth-url auth-url
                         :token-url token-url
                         :access-response result))))

;;;###autoload
(defun oauth2-refresh-access (token)
  "Refresh OAuth access TOKEN.
TOKEN should be obtained with `oauth2-request-access'."
  (if-let* ((func-name (nth 1 (backtrace-frame 2)))
            (current-timestamp (oauth2--current-timestamp))
            (request-timestamp (oauth2-token-request-timestamp token))
            (timestamp-difference (- current-timestamp request-timestamp))
            (expires-in (cdr (assoc 'expires_in
                                    (oauth2-token-access-response token))))
            (cache-valid
             (progn
               (oauth2--do-trivia (concat "%s: current-timestamp: %d, "
                                          "previous request-timestamp: %d, "
                                          "timestamp difference: %d; "
                                          "expires-in: %d, ")
                                  func-name current-timestamp request-timestamp
                                  timestamp-difference expires-in)
               (< timestamp-difference expires-in))))
      (oauth2--do-debug "%s: reusing cached access-token." func-name)

    (oauth2--do-debug "%s: requesting new access-token." func-name)
    (setf (oauth2-token-request-timestamp token) current-timestamp)
    (setf (oauth2-token-access-token token)
          (cdr (assoc 'access_token
                      (oauth2-make-access-request
                       (oauth2-token-token-url token)
                       (concat "client_id=" (oauth2-token-client-id token)
                               (when (oauth2-token-client-secret token)
                                 (concat "&client_secret="
                                         (oauth2-token-client-secret token)))
                               "&refresh_token="
                               (oauth2-token-refresh-token token)
                               "&grant_type=refresh_token")))))
    (oauth2--with-plstore
     (oauth2--update-plstore plstore token)))

  token)

;;;###autoload
(defun oauth2-auth (auth-url token-url client-id client-secret
                             &optional scope state redirect-uri)
  "Authenticate application via OAuth2."
  (oauth2-request-access
   auth-url
   token-url
   client-id
   client-secret
   (oauth2-request-authorization
    auth-url client-id scope state redirect-uri)
   redirect-uri))

(defun oauth2-compute-id (auth-url token-url scope client-id user-name)
  "Compute an unique id mainly to use as plstore id.
The result is computed using AUTH-URL, TOKEN-URL, SCOPE, CLIENT-ID, and
USER-NAME to ensure the plstore id is unique."
  (secure-hash 'sha512 (concat auth-url token-url scope client-id user-name)))

;;;###autoload
(defun oauth2-auth-and-store (auth-url token-url scope client-id client-secret
                                       &optional redirect-uri state user-name)
  "Request access to a resource and store it.
AUTH-URL and TOKEN-URL are provided by the service provider.  CLIENT-ID
and CLIENT-SECRET should be generated by the service provider when a
user registers an application.  SCOPE identifies the resources that your
application can access on the user's behalf.  STATE is a string that
your application uses to maintain the state between the request and
redirect response. USER-NAME is the login user name and is required to
provide a unique plstore id for users on the same service provider.

Returns an `oauth2-token'."
  ;; We store a MD5 sum of all URL
  (oauth2--with-plstore
   (let* ((plstore-id (oauth2-compute-id auth-url token-url scope client-id
                                         user-name))
          (plist (cdr (plstore-get plstore plstore-id))))
     (oauth2--do-trivia "user-name: %s\nplstore-id: %s"
                        user-name plstore-id)
     ;; Check if we found something matching this access
     (if plist
         ;; We did, return the token object
         (progn
           (oauth2--do-trivia "Found matching plstore-id from plstore.")
           (make-oauth2-token :plstore-id plstore-id
                              :client-id client-id
                              :client-secret client-secret
                              :access-token (plist-get plist :access-token)
                              :refresh-token (plist-get plist :refresh-token)
                              :request-timestamp (plist-get plist
                                                            :request-timestamp)
                              :auth-url auth-url
                              :token-url token-url
                              :access-response (plist-get plist
                                                          :access-response)))
       (oauth2--do-trivia "Requesting new oauth2-token.")
       (let ((token (oauth2-auth auth-url token-url
                                 client-id client-secret scope state
                                 redirect-uri)))
         ;; Set the plstore
         (setf (oauth2-token-plstore-id token) plstore-id)
         (oauth2--update-plstore plstore token)
         token)))))

(provide 'oauth2)

;;; oauth2.el ends here
