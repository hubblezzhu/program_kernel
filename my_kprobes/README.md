# my_kprobes


work in kernel 5.10, not work in kernel 6.1
because __show_free_areas() is not EXPORT in kernel 6.1, compile ko err


__show_free_areas() is a new function added in 
maybe this is a linux kernel bug
