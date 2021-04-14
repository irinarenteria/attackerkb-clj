# AttackerKB
This is a Clojure client for Rapid7's ![AttackerKB API](https://attackerkb.com), a crowd-sourced knowledge base of vulnerability intelligence.

![AKB](https://github.com/irinarenteria/attackerkb-clj/blob/main/assets/akb.png)

## Installation

[![Clojars Project](https://img.shields.io/clojars/v/attackerkb-clj.svg)](https://clojars.org/attackerkb-clj)

## Auth
Instructions on how to obtain an AttackerKB API key can be found [here](https://attackerkb.com/faq#faq_api).

## Usage

attackerkb-clj provides an interface for the AttackerKB API and offers the option of building a full record for a vulnerability (a full record includes topics and assessments).

```clojure
(ns my.ns
  (:require [attackerkb-clj.core :as akb]))

; Get all topics
@(akb/get-topics! "api-key")

; Get topics pertaining to a specific vulnerability
@(akb/get-topics! "api-key" {:name "CVE-2020-12812"})

; Get topics containing a substring search param
@(akb/get-topics! "api-key" {:q "zero-day"})

; Get a particular topic
@(akb/get-topic! :topic-id)

; Get all assessments for a particular topic
@(akb/get-assessments! "api-key" {:topic-id "123"})

; Get a particular assessment
@(akb/get-assessment! :assessment-id)

; Get all contributors created after a certain date
@(akb/get-contributors! {:created-after "date-time"})

; Get a particular contributor
@(akb/get-contributor! :contributor-id)

; Retrieving a vulnerability's full record
(ns my.ns
  (:require [attackerkb-clj.record :as akb-record]))
@(akb-record/build-full-vulnerability-record! "api-key" "CVE-2020-12812")
```

You can also adjust the size of the response and the delay between API calls when retrieving collections. AttackerKB responses have a default size of 10 and attackerkb-clj sets a default size of 500 with a delay of 3 seconds. This can be overridden by passing in a config map with the desired values:

```clojure
; Get topics pertaining to a specific vulnerability
@(akb/get-topics! "api-key" {:name "CVE-2020-12812"} {:response-size 50 :delay-ms 10000})
```

## License

Copyright © 2021

This program and the accompanying materials are made available under the
terms of the Eclipse Public License 2.0 which is available at
http://www.eclipse.org/legal/epl-2.0.

This Source Code may also be made available under the following Secondary
Licenses when the conditions for such availability set forth in the Eclipse
Public License, v. 2.0 are satisfied: GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or (at your
option) any later version, with the GNU Classpath Exception which is available
at https://www.gnu.org/software/classpath/license.html.
