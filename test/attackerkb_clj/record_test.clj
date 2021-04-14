(ns attackerkb-clj.record-test
  (:require [clojure.test :refer :all]
            [attackerkb-clj.core :as akb]
            [attackerkb-clj.record :as record]
            [aleph.http :as http]
            [manifold.deferred :as md]
            [byte-streams :as bs]
            [cheshire.core :as json]))

(def topics-200-response-parsed
  {:links {:self {:href "/v1/topics"}}
   :data [{:id "21646dbf-15ab-4075-987e-c4d90247b91b"}
          {:id "0d97457a-91f8-4886-b652-d1c0f665d2cb"}
          {:id "246ec63d-52cb-4998-9f34-5d2d248bb9f1"}
          {:id "ab1db525-9e34-4b60-a25e-10ee39926fb8"}
          {:id "0fcf7647-276b-4503-8ff9-c40d43f5182d"}
          {:id "95d73f63-0573-4ba7-8775-aa62f026c805"}
          {:id "546a1e21-7413-48b8-8e17-946876fc5ee9"}
          {:id "af3803d4-f960-412e-bf3e-147e8cace93c"}]})

(def assessments-200-responses
  [{:links {:next {:href "/v1/assessments?page=1&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "21646dbf-15ab-4075-987e-c4d90247b91b"}]}
   {:links {:next {:href "/v1/assessments?page=2&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "45a7dcfc-09ad-4eec-bf91-c897eca4e73d"}]}
   {:links {:next {:href "/v1/assessments?page=3&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "0fc8948a-e295-4f57-a675-8555bffd71e3"}]}
   {:links {:next {:href "/v1/assessments?page=4&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "6a834eb4-6fc5-4b82-ac49-7b4c57b684fe"}]}
   {:links {:next {:href "/v1/assessments?page=5&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "0525ade9-486a-482f-b911-7a13ee161544"}]}
   {:links {:next {:href "/v1/assessments?page=6&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "598cf097-cd62-4441-8be4-a6b6da568c43"}]}
   {:links {:next {:href "/v1/assessments?page=7&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "14f82255-b4de-44ad-9eb7-39c28095d87e"}]}
   {:links {:next {:href "/v1/assessments?page=8&size=500"}
            :self {:href "/v1/assessments"}}
    :data [{:id "45a7dcfc-09ad-4eec-bf91-c897eca4e73d"}]}])

(deftest test-build-full-vulnerability-record!
  (testing "Retrieving a vulnerability's full record succeeds."
    (let [topics-path "/topics"
          input-api-key "api-key-000"
          vuln-params {:name "cve-100-200-300"}
          assessment-params (atom [{:topic-id "21646dbf-15ab-4075-987e-c4d90247b91b"}
                                   {:topic-id "0d97457a-91f8-4886-b652-d1c0f665d2cb"}
                                   {:topic-id "246ec63d-52cb-4998-9f34-5d2d248bb9f1"}
                                   {:topic-id "ab1db525-9e34-4b60-a25e-10ee39926fb8"}
                                   {:topic-id "0fcf7647-276b-4503-8ff9-c40d43f5182d"}
                                   {:topic-id "95d73f63-0573-4ba7-8775-aa62f026c805"}
                                   {:topic-id "546a1e21-7413-48b8-8e17-946876fc5ee9"}
                                   {:topic-id "af3803d4-f960-412e-bf3e-147e8cace93c"}])
          config-params {:response-size 500 :delay-ms 4000}
          input-headers {:headers {:authorization (format "basic %s" input-api-key)}}
          pages assessments-200-responses
          mock-responses (atom pages)
          expected {:name "cve-100-200-300"
                    :topics (:data topics-200-response-parsed)
                    :assessments (->> pages (map :data) flatten)}]
      (with-redefs
       [akb/get-topics!
        (fn [api-key filter-params http-params]
          (is (= api-key input-api-key))
          (is (= filter-params vuln-params))
          (is (= http-params config-params))
          (:data topics-200-response-parsed))
        akb/get-assessments!
        (fn [api-key filter-params]
          (let [current-page (first @mock-responses)
                fparams (first @assessment-params)]
            (is (= api-key input-api-key))
            (is (= filter-params fparams))
            (reset! mock-responses (rest @mock-responses))
            (reset! assessment-params (rest @assessment-params))
            current-page))]
        (is (= expected @(record/build-full-vulnerability-record! input-api-key "cve-100-200-300")))))))
