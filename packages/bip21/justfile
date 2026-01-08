[group("Core")]
[doc("List all available commands.")]
@list:
  just --list --unsorted

[group("Core")]
[doc("Open repository on GitHub.")]
repo:
  open https://github.com/kotlin-bitcoin-tools/bip21

[group("Tests")]
[doc("Run all unit tests.")]
test:
  ./gradlew test

[group("Tests")]
[doc("Run a single test.")]
onetest TEST:
  ./gradlew test --tests {{TEST}}

[group("Format")]
[doc("Run the Ktlint formatter.")]
format:
  ./gradlew ktlintFormat

[group("Docs")]
[doc("Build and run the documentation website locally.")]
serve:
  ./gradlew dokkaGeneratePublicationHtml && rm -rf ./docs/api/ && mv ./build/dokka/html ./docs/api && mkdocs serve

[group("Docs")]
[doc("Build the API docs.")]
dokka:
  ./gradlew dokkaGeneratePublicationHtml

[group("Publish")]
[doc("Publish the library to Maven Local.")]
publishlocal:
  ./gradlew publishToMavenLocal --rerun-tasks

