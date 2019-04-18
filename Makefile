

.PHONY: build build-arm push push-arm shell run start start-arm stop stop-arm rm rm-arm release release-arm

build:
	pandoc -c github.css -t slidy -s  README.md -o README.html

