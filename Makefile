all: hme.exe

%.elf: linux/%.asm
	nasm -f bin -o $@ $<

%.exe: win32/%.asm
	nasm -f bin -o $@ $<
