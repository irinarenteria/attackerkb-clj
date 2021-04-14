(ns attackerkb-clj.record
  (:require [attackerkb-clj.core :as akb]
            [manifold.deferred :as md]))

(defn build-full-vulnerability-record!
  [api-key cve-id]
  (let [filter-params {:name cve-id}
        http-params {:response-size 500
                     :delay-ms 4000}]
    (md/chain
     (akb/get-topics! api-key filter-params http-params)
     (fn [topics]
       (let [topic-ids (map (fn [topic] {:topic-id (:id topic)}) topics)
             topic-batches (partition-all 5 topic-ids)]
         (md/loop [batches topic-batches
                   responses []]
           (if (seq batches)
             (let [[batch & more] batches]
               (md/chain
                (apply md/zip (map (partial akb/get-assessments! api-key) batch))
                #(md/recur (rest batches) (concat responses (flatten (map :data %))))))
             {:name cve-id
              :topics topics
              :assessments responses})))))))
