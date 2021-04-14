(defproject attackerkb-clj "0.1.0"
  :description "AttackerKB clojure interface"
  :url "https://github.com/irinarenteria/attackerkb-clj"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [aleph "0.4.6"]
                 [byte-streams "0.2.4"]
                 [manifold "0.1.9-alpha4"]
                 [camel-snake-kebab "0.4.2"]
                 [cheshire "5.10.0"]
                 [com.taoensso/timbre "5.1.2"]
                 [prismatic/schema "1.1.12"]]
  :plugins [[lein-cljfmt "0.7.0"]
            [lein-cloverage "1.2.2"]]
  :main ^:skip-aot attackerkb-clj.core
  :target-path "target/%s"
  :signing {:gpg-key "renteria.irina@gmail.com"}
  :profiles {:uberjar {:aot :all
                       :jvm-opts ["-Dclojure.compiler.direct-linking=true"]}})
