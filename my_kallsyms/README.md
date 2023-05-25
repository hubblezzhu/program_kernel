# my_kallsyms

not work, becase kallsyms_lookup_name() is not EXPORT since kernel 5.7
thus cannot use kallsyms_lookup_name() in ko
