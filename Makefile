.PHONY: build clean test install uninstall

build:
	./build.sh

clean:
	rm -rf bin/chihuaudit
	@echo "Cleaned"

test:
	@echo "Testing..."
	@sudo ./bin/chihuaudit audit > /dev/null && echo "✅ Audit works"
	@sudo ./bin/chihuaudit audit --json > /dev/null && echo "✅ JSON works"

install:
	sudo cp bin/chihuaudit /usr/local/bin/
	@echo "Installed"

uninstall:
	sudo rm -f /usr/local/bin/chihuaudit
	@echo "Uninstalled"
