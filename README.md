# sot-fov
Sea of Thieves FoV changer that allows you to get past the 90 degree limit. (Linux only)

Based on [fov_hk](https://github.com/NtLoadDriverEx/fov_hk), which is for windows only.

## Usage
1. Start Sea of Thieves, but don't press `Start Game` yet
2. `go run .`
3. Keep the `sot-fov` running
4. Enjoy having a normal FoV

## Customisation
If you want use a FoV other than 120, simply edit the constant at the top of `main.go`.

## Modus operandi
sot-fov uses ptrace to add breakpoints to the function called when the FoV is set. When the breakpoint is triggered, we store the value of `rcx`, which is the first parameter to that function. `rcx` is a pointer to struct which contains the FoV value at offset `+0x40`. The execution of the function is continued until it returns, where we override the FoV value by executing some bytecode.

It is important to keep in mind, that when setting breakpoint, we override the instruction at that address, so we must put the instruction back, rewind the instruction pointer, and take a step. We can then set the breakpoint again for next time.
