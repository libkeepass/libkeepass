#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import libkeepass
import getpass
import lxml.etree
import readline
import os

import cmd

class KeePassShell(cmd.Cmd):
    intro = 'Welcome to KeePassCmd. Type "open" to open a file'
    prompt = 'keepass>'
    root = None
    tree = None

    def do_open(self, arg):
        "Open a file"
        pwd = getpass.getpass()
        with libkeepass.open(os.path.expanduser(arg), password=pwd) as kdb:
            kdbx_data = kdb.pretty_print()
            self.root = lxml.etree.fromstring(kdbx_data)
            self.tree = lxml.etree.ElementTree(self.root)

    def do_search(self, arg):
        "Search in a file"
        if self.root is None or self.tree is None:
            print("You must open a file first")
            return
        search_term = arg
        xpath_query = (
            "//Group[EnableSearching!='false']/"
            "Entry/String["
            "(Key='Title' and re:test(Value, '{0}', 'i')) or "
            "(Key='URL' and contains(Value,'{0}'))]/..").format(search_term.replace("'", "\\'"))
        print(xpath_query)
        for e in self.root.xpath(xpath_query, namespaces={"re": "http://exslt.org/regular-expressions"}):
            print()
            groups_path = [p.find(".//Name").text for p in e.iterancestors() if p.tag == 'Group']
            print('/'.join(groups_path[::-1]))
            #print(tree.getpath(e))
            #print(lxml.etree.tostring(e).decode())
            #print(lxml.etree.tostring(e.find('.//String[Key="URL"]')).decode())
            #print(lxml.etree.tostring(e.find('.//String[Key="Password"]')))
            title = e.find('.//String[Key="Title"]/Value')
            if title is not None:
                title = title.text
            else:
                title = ''
            username = e.find('.//String[Key="UserName"]/Value').text
            password = e.find('.//String[Key="Password"]/Value').text
            url = e.find('.//String[Key="URL"]/Value').text
            print('{}:\t{} {} ({})'.format(title, username, password, url))

    def do_bye(self, arg):
        return True


if __name__ == '__main__':
    KeePassShell().cmdloop()
