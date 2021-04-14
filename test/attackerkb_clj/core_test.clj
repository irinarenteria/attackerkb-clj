(ns attackerkb-clj.core-test
  (:require [clojure.test :refer :all]
            [attackerkb-clj.core :as akb]
            [aleph.http :as http]
            [manifold.deferred :as md]
            [byte-streams :as bs]
            [cheshire.core :as json]))

; Topics
(def topics-200-raw
  {"links" {"self" {"href" "/v1/topics"}}
   "data" [{"id" "21646dbf-15ab-4075-987e-c4d90247b91b"
            "editorId" "e864184a-178e-447c-aad3-11c475147713"
            "name" "CVE-2019-15059"
            "created" "2021-04-12T20:30:07.178087Z"
            "revisionDate" "2021-04-12T20:30:07.178087Z"
            "disclosureDate" nil
            "document" "security researcher analysis"
            "metadata" {"vendor" {}
                        "cveState" "PUBLIC"
                        "vulnerable-versions" ["n/a"]}
            "score" {"attackerValue" 0
                     "exploitability" 0}
            "rapid7Analysis" nil
            "rapid7AnalysisCreated" nil
            "rapid7AnalysisRevisionDate" nil
            "tags" []
            "references" [{"id" "d69b96b0-89bf-45ea-845a-7bad7ceeefd5"}
                          {"id" "185fb225-1e1d-427a-bdce-b07cfd1b8861"}]}]})

(def single-topic-200
  {"data" {"id" "21646dbf-15ab-4075-987e-c4d90247b91b"
           "editorId" "e864184a-178e-447c-aad3-11c475147713"
           "name" "CVE-2019-15059"
           "created" "2021-04-12T20:30:07.178087Z"
           "revisionDate" "2021-04-12T20:30:07.178087Z"
           "disclosureDate" nil
           "document" "security researcher analysis"
           "metadata" {"vendor" {}
                       "cveState" "PUBLIC"
                       "vulnerable-versions" ["n/a"]}
           "score" {"attackerValue" 0
                    "exploitability" 0}
           "rapid7Analysis" nil
           "rapid7AnalysisCreated" nil
           "rapid7AnalysisRevisionDate" nil
           "tags" []
           "references" [{"id" "d69b96b0-89bf-45ea-845a-7bad7ceeefd5"}
                         {"id" "185fb225-1e1d-427a-bdce-b07cfd1b8861"}]}})

(def topics-200-response-parsed
  {:links {:self {:href "/v1/topics"}}
   :data [{:id "21646dbf-15ab-4075-987e-c4d90247b91b"
           :editor-id "e864184a-178e-447c-aad3-11c475147713"
           :name "CVE-2019-15059"
           :created "2021-04-12T20:30:07.178087Z"
           :revision-date "2021-04-12T20:30:07.178087Z"
           :disclosure-date nil
           :document "security researcher analysis"
           :metadata {:vendor {}
                      :cve-state "PUBLIC"
                      :vulnerable-versions ["n/a"]}
           :score {:attacker-value 0
                   :exploitability 0}
           :rapid-7-analysis nil
           :rapid-7-analysis-created nil
           :rapid-7-analysis-revision-date nil
           :tags []
           :references [{:id "d69b96b0-89bf-45ea-845a-7bad7ceeefd5"}
                        {:id "185fb225-1e1d-427a-bdce-b07cfd1b8861"}]}]})

(def topics-200-responses
  [{:links {:next {:href "/v1/topics?page=1&size=500"}
            :self {:href "/v1/topics"}}
    :data [{:id "21646dbf-15ab-4075-987e-c4d90247b91b"}]}
   {:links {:next {:href "/v1/topics?page=2&size=500"}
            :self {:href "/v1/topics"}}
    :data [{:id "45a7dcfc-09ad-4eec-bf91-c897eca4e73d"}]}
   {:links {:self {:href "/v1/topics"}}
    :data [{:id "a238d7e4-50ad-44ca-b112-a741282a7555"}]}])

; Assessments
(def assessments-200-raw
  {"links" {"self" {"href" "/v1/assessments"}}
   "data" [{"id" "e197f137-4e8d-4894-addb-e8538ebf0d49"
            "editorId" "28b588e1-fa8a-422b-b81f-02d1c3366397"
            "topicId" "f2b30450-1ecd-4194-9f19-6fb1171bf9cc"
            "created" "2021-04-09T02:48:38.158372Z"
            "revisionDate" "2021-04-09T23:27:41.513987Z"
            "document" "security researcher analysis"
            "score" 0
            "metadata" {"mitre-tactics" "Execution"
                        "attacker-value" 5
                        "exploitability" 5}
            "tags" [{"id" "4b0a84d2-07c6-4d9b-9710-e8ff35e4cd9d"}
                    {"id" "4f304b63-24f8-4a4d-9253-266cc43a096e"}]}]})

(def single-assessment-200
  {"data" {"id" "e197f137-4e8d-4894-addb-e8538ebf0d49"
           "editorId" "28b588e1-fa8a-422b-b81f-02d1c3366397"
           "topicId" "f2b30450-1ecd-4194-9f19-6fb1171bf9cc"
           "created" "2021-04-09T02:48:38.158372Z"
           "revisionDate" "2021-04-09T23:27:41.513987Z"
           "document" "security researcher analysis"
           "score" 0
           "metadata" {"mitre-tactics" "Execution"
                       "attacker-value" 5
                       "exploitability" 5}
           "tags" [{"id" "4b0a84d2-07c6-4d9b-9710-e8ff35e4cd9d"}
                   {"id" "4f304b63-24f8-4a4d-9253-266cc43a096e"}]}})

(def assessments-200-response-parsed
  {:links {:self {:href "/v1/assessments"}}
   :data [{:id "e197f137-4e8d-4894-addb-e8538ebf0d49"
           :editor-id "28b588e1-fa8a-422b-b81f-02d1c3366397"
           :topic-id "f2b30450-1ecd-4194-9f19-6fb1171bf9cc"
           :created "2021-04-09T02:48:38.158372Z"
           :revision-date "2021-04-09T23:27:41.513987Z"
           :document "security researcher analysis"
           :score 0
           :metadata {:mitre-tactics "Execution"
                      :attacker-value 5
                      :exploitability 5}
           :tags [{:id "4b0a84d2-07c6-4d9b-9710-e8ff35e4cd9d"}
                  {:id "4f304b63-24f8-4a4d-9253-266cc43a096e"}]}]})

(def assessments-200-responses
  [{:links {:next {:href "/v1/assessments?page=1&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "21646dbf-15ab-4075-987e-c4d90247b91b"}]}
   {:links {:next {:href "/v1/assessments?page=2&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "45a7dcfc-09ad-4eec-bf91-c897eca4e73d"}]}
   {:links {:self {:href "/v1/assessments"}}
    :data [{:id "a238d7e4-50ad-44ca-b112-a741282a7555"}]}])

; Contributors
(def contributors-200-raw
  {"links" {"self" {"href" "/v1/contributors"}}
   "data" [{"id" "e197f137-4e8d-4894-addb-e8538ebf0d49"
            "username" "interstellar"}]})

(def single-contributor-200
  {"data" {"id" "e197f137-4e8d-4894-addb-e8538ebf0d49"
           "username" "interstellar"}})

(def contributors-200-response-parsed
  {:links {:self {:href "/v1/contributors"}}
   :data [{:id "e197f137-4e8d-4894-addb-e8538ebf0d49"
           :username "interstellar"}]})

(def contributors-200-responses
  [{:links {:next {:href "/v1/contributors?page=1&size=500"}
            :self {:href "/v1/contributors"}}
    :data [{:id "21646dbf-15ab-4075-987e-c4d90247b91b"}]}
   {:links {:next {:href "/v1/contributors?page=2&size=500"}
            :self {:href "/v1/contributors"}}
    :data [{:id "45a7dcfc-09ad-4eec-bf91-c897eca4e73d"}]}
   {:links {:self {:href "/v1/contributors"}}
    :data [{:id "a238d7e4-50ad-44ca-b112-a741282a7555"}]}])

(deftest test-raw-get!
  (testing "GET request succeeds when an API key and a path are provided."
    (let [input-path "/topics"
          api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-url (str @akb/base-url input-path)
          expected {:status 200
                    :body (bs/to-input-stream (json/generate-string topics-200-raw))}]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          expected)]
        (is (= expected @(akb/raw-get! api-key input-path))))))
  (testing "GET request succeeds when params are provided."
    (let [input-path "/topics"
          api-key "api-key-000"
          params {:name "CVE-2019-15059"}
          input-headers {:headers {:authorization (format "basic %s" api-key)}
                         :query-params params}
          target-url (str @akb/base-url input-path)
          expected {:status 200
                    :body (bs/to-input-stream (json/generate-string topics-200-raw))}]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          expected)]
        (is (= expected @(akb/raw-get! api-key input-path params)))))))

(deftest test-get-endpoint!
  (testing "GET request succeeds and the response is parsed when an API key and a path are provided."
    (let [input-path "/topics"
          api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-url (str @akb/base-url input-path)
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string topics-200-raw))}
          expected topics-200-response-parsed]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-endpoint! api-key input-path))))))
  (testing "GET request succeeds and the response is parsed when params are provided."
    (let [input-path "/topics"
          api-key "api-key-000"
          params {:name "CVE-2019-15059"}
          input-headers {:headers {:authorization (format "basic %s" api-key)}
                         :query-params params}
          target-url (str @akb/base-url input-path)
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string topics-200-raw))}
          expected topics-200-response-parsed]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-endpoint! api-key input-path params)))))))

(deftest test-get-topics!
  (testing "Retrieving topics succeeds when an API key is provided and no pagination is required."
    (let [topics-path "/topics"
          api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-url (str @akb/base-url topics-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string topics-200-raw))}
          expected (:data topics-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-topics! api-key))))))
  (testing "Retrieving topics succeeds when an API key and filter params are provided."
    (let [topics-path "/topics"
          api-key "api-key-000"
          filter-params {:name "CVE-2019-15059"}
          input-headers {:headers {:authorization (format "basic %s" api-key)}
                         :query-params {:name "CVE-2019-15059"}}
          target-url (str @akb/base-url topics-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string topics-200-raw))}
          expected (:data topics-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-topics! api-key filter-params))))))
  (testing "An exception is thrown when delay-ms is below 3 seconds."
    (let [topics-path "/topics"
          api-key "api-key-000"
          filter-params {:name "CVE-2019-15059"}
          input-headers {:headers {:authorization (format "basic %s" api-key)}
                         :query-params {:name "CVE-2019-15059"}}
          target-url (str @akb/base-url topics-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string topics-200-raw))}
          expected (:data topics-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (thrown? Exception @(akb/get-topics! api-key filter-params {:delay-ms 2000}))))))
  (testing "Retrieving topics succeeds when an API key is provided and pagination is required."
    (let [topics-path "/topics"
          api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-urls [(str @akb/base-url "/topics?size=500")
                       (str @akb/base-url "/topics?page=1&size=500")
                       (str @akb/base-url "/topics?page=2&size=500")]
          pages topics-200-responses
          response-pages (map (fn [page] {:status 200
                                          :body (bs/to-input-stream (json/generate-string page))}) pages)
          mock-responses (atom response-pages)
          mock-urls (atom target-urls)
          expected (->> pages (map :data) flatten)]
      (with-redefs
       [http/get
        (fn [url headers]
          (let [current-page (first @mock-responses)
                current-url (first @mock-urls)]
            (is (= url current-url))
            (is (= headers input-headers))
            (reset! mock-responses (rest @mock-responses))
            (reset! mock-urls (rest @mock-urls))
            current-page))]
        (is (= expected @(akb/get-topics! api-key)))))))

(deftest test-get-topic!
  (testing "Retrieving a topic succeeds."
    (let [api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-url (str @akb/base-url "/topics/123")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string single-topic-200))}
          expected (-> topics-200-response-parsed :data first)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-topic! api-key "123")))))))

(deftest test-get-assessments!
  (testing "Retrieving assessments succeeds when an API key is provided and no pagination is required."
    (let [assessments-path "/assessments"
          api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-url (str @akb/base-url assessments-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string assessments-200-raw))}
          expected (:data assessments-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-assessments! api-key))))))
  (testing "Retrieving assessments succeeds when an API key and filter params are provided."
    (let [assessments-path "/assessments"
          api-key "api-key-000"
          filter-params {:id "ce070e74-0094-4302-8272-98643a79d717"}
          input-headers {:headers {:authorization (format "basic %s" api-key)}
                         :query-params filter-params}
          target-url (str @akb/base-url assessments-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string assessments-200-raw))}
          expected (:data assessments-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-assessments! api-key filter-params))))))
  (testing "An exception is thrown when delay-ms is below 3 seconds."
    (let [assessments-path "/assessments"
          api-key "api-key-000"
          filter-params {:name "CVE-2019-15059"}
          input-headers {:headers {:authorization (format "basic %s" api-key)}
                         :query-params {:name "CVE-2019-15059"}}
          target-url (str @akb/base-url assessments-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string assessments-200-raw))}
          expected (:data assessments-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (thrown? Exception @(akb/get-assessments! api-key filter-params {:delay-ms 2000}))))))
  (testing "Retrieving assessments succeeds when an API key is provided and pagination is required."
    (let [assessments-path "/assessments"
          api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-urls [(str @akb/base-url "/assessments?size=500")
                       (str @akb/base-url "/assessments?page=1&size=500")
                       (str @akb/base-url "/assessments?page=2&size=500")]
          pages assessments-200-responses
          response-pages (map (fn [page] {:status 200
                                          :body (bs/to-input-stream (json/generate-string page))}) pages)
          mock-responses (atom response-pages)
          mock-urls (atom target-urls)
          expected (->> pages (map :data) flatten)]
      (with-redefs
       [http/get
        (fn [url headers]
          (let [current-page (first @mock-responses)
                current-url (first @mock-urls)]
            (is (= url current-url))
            (is (= headers input-headers))
            (reset! mock-responses (rest @mock-responses))
            (reset! mock-urls (rest @mock-urls))
            current-page))]
        (is (= expected @(akb/get-assessments! api-key)))))))

(deftest test-get-assessment!
  (testing "Retrieving a assessment succeeds."
    (let [api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-url (str @akb/base-url "/assessments/123")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string single-assessment-200))}
          expected (-> assessments-200-response-parsed :data first)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-assessment! api-key "123")))))))

(deftest test-get-contributors!
  (testing "Retrieving contributors succeeds when an API key is provided and no pagination is required."
    (let [contributors-path "/contributors"
          api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-url (str @akb/base-url contributors-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string contributors-200-raw))}
          expected (:data contributors-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-contributors! api-key))))))
  (testing "Retrieving contributors succeeds when an API key and filter params are provided."
    (let [contributors-path "/contributors"
          api-key "api-key-000"
          filter-params {:id "ce070e74-0094-4302-8272-98643a79d717"}
          input-headers {:headers {:authorization (format "basic %s" api-key)}
                         :query-params filter-params}
          target-url (str @akb/base-url contributors-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string contributors-200-raw))}
          expected (:data contributors-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-contributors! api-key filter-params))))))
  (testing "An exception is thrown when delay-ms is below 3 seconds."
    (let [contributors-path "/contributors"
          api-key "api-key-000"
          filter-params {:username "interstellar"}
          input-headers {:headers {:authorization (format "basic %s" api-key)}
                         :query-params {:username "interstellar"}}
          target-url (str @akb/base-url contributors-path "?size=500")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string contributors-200-raw))}
          expected (:data contributors-200-response-parsed)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (thrown? Exception @(akb/get-contributors! api-key filter-params {:delay-ms 2000}))))))
  (testing "Retrieving contributors succeeds when an API key is provided and pagination is required."
    (let [contributors-path "/contributors"
          api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-urls [(str @akb/base-url "/contributors?size=500")
                       (str @akb/base-url "/contributors?page=1&size=500")
                       (str @akb/base-url "/contributors?page=2&size=500")]
          pages contributors-200-responses
          response-pages (map (fn [page] {:status 200
                                          :body (bs/to-input-stream (json/generate-string page))}) pages)
          mock-responses (atom response-pages)
          mock-urls (atom target-urls)
          expected (->> pages (map :data) flatten)]
      (with-redefs
       [http/get
        (fn [url headers]
          (let [current-page (first @mock-responses)
                current-url (first @mock-urls)]
            (is (= url current-url))
            (is (= headers input-headers))
            (reset! mock-responses (rest @mock-responses))
            (reset! mock-urls (rest @mock-urls))
            current-page))]
        (is (= expected @(akb/get-contributors! api-key)))))))

(deftest test-get-contributor!
  (testing "Retrieving a contributor succeeds."
    (let [api-key "api-key-000"
          input-headers {:headers {:authorization (format "basic %s" api-key)}}
          target-url (str @akb/base-url "/contributors/123")
          raw-response {:status 200
                        :body (bs/to-input-stream (json/generate-string single-contributor-200))}
          expected (-> contributors-200-response-parsed :data first)]
      (with-redefs
       [http/get
        (fn [url headers]
          (is (= url target-url))
          (is (= headers input-headers))
          raw-response)]
        (is (= expected @(akb/get-contributor! api-key "123")))))))
