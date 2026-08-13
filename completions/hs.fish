# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_hs_global_optspecs
    string join \n n/dry-run h/help
end

function __fish_hs_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_hs_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_hs_using_subcommand
    set -l cmd (__fish_hs_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c hs -n "__fish_hs_needs_command" -s n -l dry-run -d 'Do nothing, print dry-run message'
complete -c hs -n "__fish_hs_needs_command" -s h -l help -d 'Print help'
complete -c hs -n "__fish_hs_needs_command" -f -a "gen-key" -d 'Generate a key pair (ML-KEM + ML-DSA), passphrase-encrypted'
complete -c hs -n "__fish_hs_needs_command" -f -a "sign" -d 'Sign HTML blocks matching a CSS selector'
complete -c hs -n "__fish_hs_needs_command" -f -a "verify" -d 'Verify signed blocks in an HTML file'
complete -c hs -n "__fish_hs_needs_command" -f -a "view-key" -d 'Display information about a key file'
complete -c hs -n "__fish_hs_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c hs -n "__fish_hs_using_subcommand gen-key" -s o -l output -d 'Output path for the secret key file' -r
complete -c hs -n "__fish_hs_using_subcommand gen-key" -l public-key -d 'Write the armored public key to this path' -r
complete -c hs -n "__fish_hs_using_subcommand gen-key" -l kem -d 'KEM algorithm variant: ML-KEM-512, ML-KEM-768, ML-KEM-1024' -r
complete -c hs -n "__fish_hs_using_subcommand gen-key" -l dsa -d 'Digital signature variant: ML-DSA-44, ML-DSA-65, ML-DSA-87' -r
complete -c hs -n "__fish_hs_using_subcommand gen-key" -l passphrase-file -d 'Read the passphrase from a file (first line)' -r
complete -c hs -n "__fish_hs_using_subcommand gen-key" -l argon2-mem -d 'Argon2id memory cost in KiB (default 65536 ~= 64 MiB)' -r
complete -c hs -n "__fish_hs_using_subcommand gen-key" -l argon2-time -d 'Argon2id time cost / iterations (default 3)' -r
complete -c hs -n "__fish_hs_using_subcommand gen-key" -l argon2-par -d 'Argon2id parallelism / threads (default 1)' -r
complete -c hs -n "__fish_hs_using_subcommand gen-key" -l no-passphrase -d 'Store the key without a passphrase'
complete -c hs -n "__fish_hs_using_subcommand gen-key" -s n -l dry-run -d 'Do nothing, print dry-run message'
complete -c hs -n "__fish_hs_using_subcommand gen-key" -s h -l help -d 'Print help'
complete -c hs -n "__fish_hs_using_subcommand sign" -s k -l key -d 'Path to the secret key file (.hskey)' -r
complete -c hs -n "__fish_hs_using_subcommand sign" -l passphrase-file -d 'Read the passphrase from a file (first line)' -r
complete -c hs -n "__fish_hs_using_subcommand sign" -s o -l output -d 'Output HTML file path' -r
complete -c hs -n "__fish_hs_using_subcommand sign" -l no-passphrase -d 'Use an empty passphrase (no prompt)'
complete -c hs -n "__fish_hs_using_subcommand sign" -s n -l dry-run -d 'Do nothing, print dry-run message'
complete -c hs -n "__fish_hs_using_subcommand sign" -s h -l help -d 'Print help'
complete -c hs -n "__fish_hs_using_subcommand verify" -s k -l key -d 'Require blocks to be signed with this armored public key' -r
complete -c hs -n "__fish_hs_using_subcommand verify" -l ignore-tls-errors -d 'Skip TLS certificate validation when verifying a URL'
complete -c hs -n "__fish_hs_using_subcommand verify" -s n -l dry-run -d 'Do nothing, print dry-run message'
complete -c hs -n "__fish_hs_using_subcommand verify" -s h -l help -d 'Print help'
complete -c hs -n "__fish_hs_using_subcommand view-key" -s k -l key -d 'Path to the secret key file (.hskey)' -r
complete -c hs -n "__fish_hs_using_subcommand view-key" -l passphrase-file -d 'Read the passphrase from a file (first line)' -r
complete -c hs -n "__fish_hs_using_subcommand view-key" -l no-passphrase -d 'Use an empty passphrase (no prompt)'
complete -c hs -n "__fish_hs_using_subcommand view-key" -s n -l dry-run -d 'Do nothing, print dry-run message'
complete -c hs -n "__fish_hs_using_subcommand view-key" -s h -l help -d 'Print help'
complete -c hs -n "__fish_hs_using_subcommand help; and not __fish_seen_subcommand_from gen-key sign verify view-key help" -f -a "gen-key" -d 'Generate a key pair (ML-KEM + ML-DSA), passphrase-encrypted'
complete -c hs -n "__fish_hs_using_subcommand help; and not __fish_seen_subcommand_from gen-key sign verify view-key help" -f -a "sign" -d 'Sign HTML blocks matching a CSS selector'
complete -c hs -n "__fish_hs_using_subcommand help; and not __fish_seen_subcommand_from gen-key sign verify view-key help" -f -a "verify" -d 'Verify signed blocks in an HTML file'
complete -c hs -n "__fish_hs_using_subcommand help; and not __fish_seen_subcommand_from gen-key sign verify view-key help" -f -a "view-key" -d 'Display information about a key file'
complete -c hs -n "__fish_hs_using_subcommand help; and not __fish_seen_subcommand_from gen-key sign verify view-key help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
