(ns attackerkb-clj.schemas
  (:require [schema.core :as schema]))

(def TopicsParams
  "Schema for parameters accepted by the topics endpoint."
  {(schema/optional-key :id) schema/Str
   (schema/optional-key :editor-id) schema/Str
   (schema/optional-key :name) schema/Str
   (schema/optional-key :created) schema/Str
   (schema/optional-key :created-after) schema/Str
   (schema/optional-key :created-before) schema/Str
   (schema/optional-key :revision-date) schema/Str
   (schema/optional-key :revised-after) schema/Str
   (schema/optional-key :revised-before) schema/Str
   (schema/optional-key :disclosureDate) schema/Str
   (schema/optional-key :document) schema/Str
   (schema/optional-key :metadata) schema/Str
   (schema/optional-key :featured) schema/Bool
   (schema/optional-key :rapid7-analysis-created) schema/Str
   (schema/optional-key :rapid7-analysis-created-after) schema/Str
   (schema/optional-key :rapid7-analysis-created-before) schema/Str
   (schema/optional-key :rapid7-analysis-revision-date) schema/Str
   (schema/optional-key :rapid7-analysis-revised-after) schema/Str
   (schema/optional-key :rapid7-analysis-revised-before) schema/Str
   (schema/optional-key :q) schema/Str
   (schema/optional-key :sort) schema/Str
   (schema/optional-key :expand) schema/Str})

(def TopicId
  {(schema/required-key :id) schema/Str})

(def AssessmentsParams
  "Schema for parameters accepted by the assessments endpoint."
  {(schema/optional-key :id) schema/Str
   (schema/optional-key :editor-id) schema/Str
   (schema/optional-key :topic-id) schema/Str
   (schema/optional-key :created) schema/Str
   (schema/optional-key :created-after) schema/Str
   (schema/optional-key :created-before) schema/Str
   (schema/optional-key :revision-date) schema/Str
   (schema/optional-key :revised-after) schema/Str
   (schema/optional-key :revised-before) schema/Str
   (schema/optional-key :document) schema/Str
   (schema/optional-key :score) schema/Int
   (schema/optional-key :metadata) schema/Str
   (schema/optional-key :q) schema/Str
   (schema/optional-key :sort) schema/Str
   (schema/optional-key :expand) schema/Str})

(def AssessmentId
  {(schema/required-key :id) schema/Str})

(def ContributorsParams
  "Schema for parameters accepted by the contributors endpoint."
  {(schema/optional-key :id) schema/Str
   (schema/optional-key :username) schema/Str
   (schema/optional-key :avatar) schema/Str
   (schema/optional-key :created) schema/Str
   (schema/optional-key :created-after) schema/Str
   (schema/optional-key :created-before) schema/Str
   (schema/optional-key :score) schema/Int
   (schema/optional-key :q) schema/Str
   (schema/optional-key :sort) schema/Str})

(def ContributorId
  {(schema/required-key :id) schema/Str})
