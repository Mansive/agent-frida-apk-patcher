Patch Eden (and probably Vita3K too) with frida-gadget v16.7.11 compiled without `SIGSEGV` and `SIGBUS` signal handling. That `frida-gadget` comes precompiled in the `assets` directory, but if you want to compile your own then comment out the signals in question in [frida-gum](https://github.com/frida/frida-gum/blob/742d69e4be49ac76acc5ac7aa4a3c0bb57351c08/gum/backend-posix/gumexceptor-posix.c#L231) and follow instructions from [frida](https://github.com/frida/frida).

Vibecoded with Gemini 3
