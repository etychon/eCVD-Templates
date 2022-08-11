#!/usr/bin/python3

## Copyright 2022 Emmanuel Tychon
## Use of this source code is governed by an MIT-style
## license that can be found in the LICENSE file or at
## https://opensource.org/licenses/MIT.

## This code is an individual contribution not endorsed, nor supported by Cisco

# This script will read the file userPropertyTypes.xml, parse it, and 
# create a table showing which platform(s) are supporting which variables.
# This is a much easier to consume information.
# The output filename is userPropertyTypes-for-humans.txt

import xml.dom.minidom

# This will be a dictionary of lists
t_output = {} 

def main():

    # This is a list all possible platform 
    all_platforms = []

    # Load the UPT file in XML
    doc = xml.dom.minidom.parse("UPT/userPropertyTypes.xml")

    # Open file for saving output
    f = open("UPT/userPropertyTypes-for-humans.txt", "w")

    # Get the list of propertyTypes section
    # Each section define attributes for one or multiple platform(s)
    allPropsPlatforms = doc.getElementsByTagName("propertyTypes")

    for pp in allPropsPlatforms:
        # Get in list t_plat all the platforms for which those attributes apply
        t_plat = pp.getAttribute("kind").split(',')
        # Add platforms to list of all platforms if not already in there
        all_platforms = list(set(all_platforms + t_plat))
        print("*** {} ***".format(pp.getAttribute("kind")))
        # Iterate over all properties for these platforms
        for entry in pp.getElementsByTagName('propertyType'):
            # Get property name
            z = entry.getElementsByTagName("name")[0].childNodes[0].data
            if z not in t_output:
                # This propery is not in dict yet, initialize empty list
                t_output[z] = []
            # Add those platforms as supported for this property
            t_output[z].append(t_plat)

    # Print headers
    print('{:<38}'.format("Attribute Name"),end="",file=f)
    all_platforms.sort()
    for p in all_platforms:
        print('{:<8}'.format(p),end="",file=f)
    print('\n' + '-' * 78,file=f)

    # Let's go through all attributes stored in t_output dict
    for attr in t_output.keys():
        # Print attribute
        print('{:<38}'.format(attr),end="",file=f)
        # Get list of supported platforms for this attribute
        # Remember that t_output is a dict of lists
        plat = t_output[attr][0]
        # For each atribute let's go through all platforms
        for p in all_platforms:
            # use lambda function to check if attribute 'attr' is supported on platform 'p'
            print('{:<8}'.format((lambda p, plat : "yes" if p in plat else "no")(p , plat)), end="",file=f)
        print('',file=f)

    f.close()


if __name__ == "__main__":
    main()

