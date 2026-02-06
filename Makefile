.PHONY: build build-cloud clean test install install-cloud uninstall

build:
	./build.sh

build-cloud:
	./build.sh cloud

clean:
	rm -rf bin/chihuaudit bin/chihuaudit-cloud
	@echo "Cleaned"

test:
	@echo "Testing..."
	@sudo ./bin/chihuaudit audit > /dev/null && echo "✅ Audit works"
	@sudo ./bin/chihuaudit audit --json > /dev/null && echo "✅ JSON works"

install:
	sudo cp bin/chihuaudit /usr/local/bin/
	@echo "Installed"

install-cloud:
	sudo cp bin/chihuaudit-cloud /usr/local/bin/
	@echo "Installed chihuaudit-cloud"

uninstall:
	sudo rm -f /usr/local/bin/chihuaudit
	@echo "Uninstalled"
