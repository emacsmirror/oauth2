(require 'oauth2)
(require 'ert)

(ert-deftest oauth2--build-url-param-str-test ()
  (should (string=
           (oauth2--build-url-param-str "simple" "plain"
                                        "empty" nil
                                        "empty2" ""
                                        "email" "a@example.com")
           "simple=plain&email=a%40example.com"))
  (should (string=
           (oauth2--build-url-param-str "url" "http://localhost"
                                        "random" "12+3_4_=5=/6/")
           "url=http%3A%2F%2Flocalhost&random=12%2B3_4_%3D5%3D%2F6%2F"))
  (should-error (oauth2--build-url-param-str "novalue")
                :type 'error))

(ert-deftest oauth2--build-url-test ()
  (should (string=
           (oauth2--build-url "http://127.0.0.1"
                              "request=auth&login_hint=manphiz%40outlook.com")
           "http://127.0.0.1?request=auth&login_hint=manphiz%40outlook.com"))
  (should (string=
           (oauth2--build-url "https://localhost"
                              "simple" "plain"
                              "empty" nil
                              "complex" "1+2@3#4_5/6"
                              "empty2" "")
           "https://localhost?simple=plain&complex=1%2B2%403%234_5%2F6")))
