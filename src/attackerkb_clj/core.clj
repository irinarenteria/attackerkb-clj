(ns attackerkb-clj.core
  (:require
   [clojure.string :as str]
   [camel-snake-kebab.core :refer [->kebab-case-keyword]]
   [manifold.deferred :as md]
   [aleph.http :as http]
   [cheshire.core :as json]
   [byte-streams :as bs]
   [taoensso.timbre :as timbre :refer [info]]
   [schema.core :as schema]
   [attackerkb-clj.schemas :refer :all])
  (:gen-class))

(def base-url (atom "https://api.attackerkb.com/v1"))

(defn ^:private construct-auth-header
  [api-key]
  (let [header (format "basic %s" api-key)]
    {:headers {:authorization header}}))

(defn ^:private construct-headers
  ([api-key]
   (construct-auth-header api-key))
  ([api-key params]
   (merge
    (construct-auth-header api-key)
    {:query-params params})))

(defn ^:private parse-response
  [response]
  (-> response
      :body
      bs/to-reader
      (json/parse-stream ->kebab-case-keyword)))

(defn raw-get!
  ([api-key path]
   (info "Retrieving" (str @base-url path))
   (let [url (str @base-url path)
         headers (construct-headers api-key)]
     (md/future
       (http/get
        url
        headers))))
  ([api-key path params]
   (info "Retrieving" (str @base-url path))
   (let [url (str @base-url path)
         headers (construct-headers api-key params)]
     (md/future
       (http/get
        url
        headers)))))

(defn get-endpoint!
  [api-key path & [filtering-params]]
  (if filtering-params
    (md/chain
     (raw-get! api-key path filtering-params)
     parse-response)
    (md/chain
     (raw-get! api-key path)
     parse-response)))

(defn ^:private paginate-response
  [api-key response config-params]
  (if (< (:delay-ms config-params) 3000)
    (throw (Exception. "The delay between API calls cannot be set to lower than 3 seconds."))
    (let [first-page (:data response)
          format-next-url (fn [next] (-> next (str/split #"/v1") last))]
      (md/loop [all-pages first-page
                next-page response]
        (if (contains? (:links next-page) :next)
          (let [next (-> next-page :links :next :href)]
            (md/chain
             (get-endpoint! api-key (format-next-url next))
             (fn [np]
               (Thread/sleep (:delay-ms config-params))
               np)
             #(md/recur (concat all-pages (:data %)) %)))
          all-pages)))))

(defn get-topics!
  [api-key & [filter-params {:keys [response-size delay-ms] :or {response-size 500 delay-ms 3000}}]]
  (let [target-path (format "/topics?size=%s" response-size)
        request-config {:response-size response-size :delay-ms delay-ms}]
    (when filter-params
      (schema/validate TopicsParams filter-params))
    (md/chain
     (get-endpoint! api-key target-path filter-params)
     #(paginate-response api-key % request-config))))

(defn get-topic!
  [api-key topic-id]
  (let [target-path (format "/topics/%s" topic-id)]
    (schema/validate TopicId {:id topic-id})
    (md/chain
     (get-endpoint! api-key target-path)
     :data)))

(defn get-assessments!
  [api-key & [filter-params {:keys [response-size delay-ms] :or {response-size 500 delay-ms 3000}}]]
  (let [target-path (format "/assessments?size=%s" response-size)
        request-config {:response-size response-size :delay-ms delay-ms}]
    (when filter-params
      (schema/validate AssessmentsParams filter-params))
    (md/chain
     (get-endpoint! api-key target-path filter-params)
     #(paginate-response api-key % request-config))))

(defn get-assessment!
  [api-key assessment-id]
  (let [target-path (format "/assessments/%s" assessment-id)]
    (schema/validate AssessmentId {:id assessment-id})
    (md/chain
     (get-endpoint! api-key target-path)
     :data)))

(defn get-contributors!
  [api-key & [filter-params {:keys [response-size delay-ms] :or {response-size 500 delay-ms 3000}}]]
  (let [target-path (format "/contributors?size=%s" response-size)
        request-config {:response-size response-size :delay-ms delay-ms}]
    (when filter-params
      (schema/validate ContributorsParams filter-params))
    (md/chain
     (get-endpoint! api-key target-path filter-params)
     #(paginate-response api-key % request-config))))

(defn get-contributor!
  [api-key contributor-id]
  (let [target-path (format "/contributors/%s" contributor-id)]
    (schema/validate ContributorId {:id contributor-id})
    (md/chain
     (get-endpoint! api-key target-path)
     :data)))
