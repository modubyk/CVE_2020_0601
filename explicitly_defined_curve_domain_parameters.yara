rule explicitly_defined_curve_domain_parameters
{
    strings:
        $ = { 06 07 2a 86 48 ce 3d 02 01 30 82 [2] 02 01 01 30 3c 06 07 2a 86 48 ce 3d 01 01 }

    condition: all of them
}