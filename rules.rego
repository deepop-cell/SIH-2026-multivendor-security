package network.security

default deny = false

deny if {
    [path, val] := walk(input)
    val == 1
}

deny if {
    [path, val] := walk(input)
    val == "1"
}

deny if {
    [path, val] := walk(input)
    val == "v1"
}

deny if {
    [path, val] := walk(input)
    key := path[count(path) - 1]
    contains(lower(key), "telnet")
}

deny if {
    [path, val] := walk(input)
    is_string(val)
    contains(lower(val), "telnet")
}