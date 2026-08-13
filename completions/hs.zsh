#compdef hs

autoload -U is-at-least

_hs() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'-n[Do nothing, print dry-run message]' \
'--dry-run[Do nothing, print dry-run message]' \
'-h[Print help]' \
'--help[Print help]' \
":: :_hs_commands" \
"*::: :->hs" \
&& ret=0
    case $state in
    (hs)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:hs-command-$line[1]:"
        case $line[1] in
            (gen-key)
_arguments "${_arguments_options[@]}" : \
'-o+[Output path for the secret key file]:OUTPUT:_default' \
'--output=[Output path for the secret key file]:OUTPUT:_default' \
'--public-key=[Write the armored public key to this path]:PUBLIC_KEY:_default' \
'--kem=[KEM algorithm variant\: ML-KEM-512, ML-KEM-768, ML-KEM-1024]:KEM:_default' \
'--dsa=[Digital signature variant\: ML-DSA-44, ML-DSA-65, ML-DSA-87]:DSA:_default' \
'--passphrase-file=[Read the passphrase from a file (first line)]:PASSPHRASE_FILE:_default' \
'--argon2-mem=[Argon2id memory cost in KiB (default 65536 ~= 64 MiB)]:ARGON2_MEM:_default' \
'--argon2-time=[Argon2id time cost / iterations (default 3)]:ARGON2_TIME:_default' \
'--argon2-par=[Argon2id parallelism / threads (default 1)]:ARGON2_PAR:_default' \
'--no-passphrase[Store the key without a passphrase]' \
'-n[Do nothing, print dry-run message]' \
'--dry-run[Do nothing, print dry-run message]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
'-k+[Path to the secret key file (.hskey)]:KEY:_default' \
'--key=[Path to the secret key file (.hskey)]:KEY:_default' \
'--passphrase-file=[Read the passphrase from a file (first line)]:PASSPHRASE_FILE:_default' \
'-o+[Output HTML file path]:OUTPUT:_default' \
'--output=[Output HTML file path]:OUTPUT:_default' \
'--no-passphrase[Use an empty passphrase (no prompt)]' \
'-n[Do nothing, print dry-run message]' \
'--dry-run[Do nothing, print dry-run message]' \
'-h[Print help]' \
'--help[Print help]' \
':file -- HTML file to sign:_default' \
':selector -- CSS selector of the block(s) to sign:_default' \
&& ret=0
;;
(verify)
_arguments "${_arguments_options[@]}" : \
'-k+[Require blocks to be signed with this public key (armored or .hskey)]:KEY:_default' \
'--key=[Require blocks to be signed with this public key (armored or .hskey)]:KEY:_default' \
'--passphrase-file=[Read the passphrase from a file (first line)]:PASSPHRASE_FILE:_default' \
'--ignore-tls-errors[Skip TLS certificate validation when verifying a URL]' \
'--format=[Output format: text (default) or json]:FORMAT:(text json)' \
'--no-passphrase[Use an empty passphrase (no prompt)]' \
'-n[Do nothing, print dry-run message]' \
'--dry-run[Do nothing, print dry-run message]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':file -- HTML file or URL to verify:_default' \
&& ret=0
;;
(export)
_arguments "${_arguments_options[@]}" : \
'-k+[Path to the secret key file (.hskey)]:KEY:_default' \
'--key=[Path to the secret key file (.hskey)]:KEY:_default' \
'-o+[Write the public key to this file]:OUTPUT:_default' \
'--output=[Write the public key to this file]:OUTPUT:_default' \
'--url+[URL of the public key to publish in the _hs_key DNS pin record]:URL:_urls' \
'--passphrase-file=[Read the passphrase from a file (first line)]:PASSPHRASE_FILE:_default' \
'--txt[Output the HSPIN:SHA3-256:<fingerprint>:<url> DNS TXT record (requires --url)]' \
'--no-passphrase[Use an empty passphrase (no prompt)]' \
'-n[Do nothing, print dry-run message]' \
'--dry-run[Do nothing, print dry-run message]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(view-key)
_arguments "${_arguments_options[@]}" : \
'-k+[Path to the secret key file (.hskey)]:KEY:_default' \
'--key=[Path to the secret key file (.hskey)]:KEY:_default' \
'--passphrase-file=[Read the passphrase from a file (first line)]:PASSPHRASE_FILE:_default' \
'--no-passphrase[Use an empty passphrase (no prompt)]' \
'-n[Do nothing, print dry-run message]' \
'--dry-run[Do nothing, print dry-run message]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_hs__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:hs-help-command-$line[1]:"
        case $line[1] in
            (gen-key)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sign)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(verify)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(export)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(view-key)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_hs_commands] )) ||
_hs_commands() {
    local commands; commands=(
'gen-key:Generate a key pair (ML-KEM + ML-DSA), passphrase-encrypted' \
'sign:Sign HTML blocks matching a CSS selector' \
'verify:Verify signed blocks in an HTML file' \
'export:Export the public key of a key file (armored, or a DNS pin record)' \
'view-key:Display information about a key file' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'hs commands' commands "$@"
}
(( $+functions[_hs__subcmd__export_commands] )) ||
_hs__subcmd__export_commands() {
    local commands; commands=()
    _describe -t commands 'hs export commands' commands "$@"
}
(( $+functions[_hs__subcmd__gen-key_commands] )) ||
_hs__subcmd__gen-key_commands() {
    local commands; commands=()
    _describe -t commands 'hs gen-key commands' commands "$@"
}
(( $+functions[_hs__subcmd__help_commands] )) ||
_hs__subcmd__help_commands() {
    local commands; commands=(
'gen-key:Generate a key pair (ML-KEM + ML-DSA), passphrase-encrypted' \
'sign:Sign HTML blocks matching a CSS selector' \
'verify:Verify signed blocks in an HTML file' \
'export:Export the public key of a key file (armored, or a DNS pin record)' \
'view-key:Display information about a key file' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'hs help commands' commands "$@"
}
(( $+functions[_hs__subcmd__help__subcmd__export_commands] )) ||
_hs__subcmd__help__subcmd__export_commands() {
    local commands; commands=()
    _describe -t commands 'hs help export commands' commands "$@"
}
(( $+functions[_hs__subcmd__help__subcmd__gen-key_commands] )) ||
_hs__subcmd__help__subcmd__gen-key_commands() {
    local commands; commands=()
    _describe -t commands 'hs help gen-key commands' commands "$@"
}
(( $+functions[_hs__subcmd__help__subcmd__help_commands] )) ||
_hs__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'hs help help commands' commands "$@"
}
(( $+functions[_hs__subcmd__help__subcmd__sign_commands] )) ||
_hs__subcmd__help__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'hs help sign commands' commands "$@"
}
(( $+functions[_hs__subcmd__help__subcmd__verify_commands] )) ||
_hs__subcmd__help__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'hs help verify commands' commands "$@"
}
(( $+functions[_hs__subcmd__help__subcmd__view-key_commands] )) ||
_hs__subcmd__help__subcmd__view-key_commands() {
    local commands; commands=()
    _describe -t commands 'hs help view-key commands' commands "$@"
}
(( $+functions[_hs__subcmd__sign_commands] )) ||
_hs__subcmd__sign_commands() {
    local commands; commands=()
    _describe -t commands 'hs sign commands' commands "$@"
}
(( $+functions[_hs__subcmd__verify_commands] )) ||
_hs__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'hs verify commands' commands "$@"
}
(( $+functions[_hs__subcmd__view-key_commands] )) ||
_hs__subcmd__view-key_commands() {
    local commands; commands=()
    _describe -t commands 'hs view-key commands' commands "$@"
}

if [ "$funcstack[1]" = "_hs" ]; then
    _hs "$@"
else
    compdef _hs hs
fi
