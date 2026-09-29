.DEFAULT_GOAL := help

.PHONY: help flash

help:
	@echo "Run 'make flash' to flash second-movement and update its current.uf2 reference."

flash:
	bin/firmware_flasher.py --reference ../second-movement/current.uf2 ../second-movement/build/firmware.uf2
	cp ../second-movement/build/firmware.uf2 ../second-movement/current.uf2
