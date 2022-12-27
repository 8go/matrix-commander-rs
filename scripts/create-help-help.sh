#!/usr/bin/env bash
PATH=".:./target/release/:./target/debug/:$PATH" &&
    matrix-commander-rs --help >help.help.txt
echo "help.help.txt is $(wc -l help.help.txt | cut -d ' ' -f1) lines long"

# ALTERNATIVE:
# #!/usr/bin/env bash
# old_width=$(stty size | cut -d' ' -f2-) && stty cols 69 && cargo run -- --help >help.help.txt &&
#     stty cols $old_width && stty size && echo -n "Max width: " && wc -L help.help.txt
# sed -i "s|target/debug/matrix-commander-rs|matrix-commander-rs|g" help.help.txt
# # remove color codes, bold and underline char sequences
# sed -i "s,\x1B\[[0-9;]*[a-zA-Z],,g" help.help.txt 
