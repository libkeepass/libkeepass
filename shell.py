#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import re
import binascii

import libkeepass
import getpass
import lxml.etree
import readline
import os
import sys

import cmd


class KeePassShell(cmd.Cmd):
    intro = 'Welcome to KeePassShell. Type "open" to open a file'
    prompt = 'keepass>'
    filename = ''
    root = None
    tree = None
    current_group = None
    current_path = ''
    _globals = {}
    _locals = {}  # Initialize execution namespace for user
    _hist = []  # No history yet

    def do_open(self, arg):
        """Open a file"""
        pwd = getpass.getpass()
        try:
            with libkeepass.open(os.path.expanduser(arg), password=pwd) as kdb:
                kdbx_data = kdb.pretty_print()
                self.root = lxml.etree.fromstring(kdbx_data)
                self.tree = lxml.etree.ElementTree(self.root)
                self.current_group = self.tree.xpath("/KeePassFile/Root/Group")[0]
                self.current_path = '/' + self.current_group.find('Name').text
                self.filename = arg
                self.prompt = self._prompt()
        except OSError as ex:
            print(ex)

    def _prompt(self):
        prompt = 'keepass'
        if self.filename != '':
            prompt += ':({})'.format(self.filename)
        if self.current_path != '':
            prompt += self.current_path
        prompt += '>'
        return prompt


    def do_search(self, arg):
        """Search in a file"""
        if self.root is None or self.tree is None:
            print("You must open a file first")
            return
        search_term = arg
        xpath_query = (
            "//Group[EnableSearching!='false']/"
            "Entry/String["
            "(Key='Title' and re:test(Value, '{0}', 'i')) or "
            "(Key='URL' and contains(Value,'{0}'))]/..").format(search_term.replace("'", "\\'"))
        # print(xpath_query)
        for e in self.root.xpath(xpath_query, namespaces={"re": "http://exslt.org/regular-expressions"}):
            print()
            groups_path = [p.find(".//Name").text for p in e.iterancestors() if p.tag == 'Group']
            print('/'.join(groups_path[::-1]))
            # print(tree.getpath(e))
            # print(lxml.etree.tostring(e).decode())
            # print(lxml.etree.tostring(e.find('.//String[Key="URL"]')).decode())
            # print(lxml.etree.tostring(e.find('.//String[Key="Password"]')))
            title = e.find('.//String[Key="Title"]/Value')
            if title is not None:
                title = title.text
            else:
                title = ''
            username = e.find('.//String[Key="UserName"]/Value').text
            password = e.find('.//String[Key="Password"]/Value').text
            url = e.find('.//String[Key="URL"]/Value').text
            print('{}:\t{} {} ({})'.format(title, username, password, url))

    # def do_attach(self, arg):
    # """Manage attachments: attach <path to entry|entry number>"""
    # pass

    def complete_cd(self, text, line, begidx, endidx):
        return [g for g in self._groups() if g.lower().startswith(text.lower())]

    def do_cd(self, arg):
        """Change directory (path to a group)"""
        if arg == '..':
            # go up
            parent = self.current_group.getparent()
            if parent.tag == 'Group':
                self.current_group = parent
                self.current_path = '/'.join(self.current_path.split('/')[0:-1])
            else:
                print("Already at top folder")
        else:
            groups = self._groups()
            if arg in groups:
                new_group = self.current_group.find("Group[Name='{}']".format(arg))
            elif re.match('\d+', arg) and int(arg) < len(groups):
                new_group = self.current_group.find("Group[Name='{}']".format(groups[int(arg)]))
            else:
                print("Group not found:", arg)
                return
            self.current_path += '/' + new_group.find('Name').text
            self.current_group = new_group

    # def do_cl(self, arg):
    # """Change directory and list entries (cd+ls)"""
    # pass
    #
    # def do_clone(self, arg):
    # """Clone an entry: clone <path to entry> <path to new entry>"""
    # pass
    #
    # def do_close(self, arg):
    # """Close the currently opened database"""
    # pass
    #
    # def do_cls(self, arg):
    # """Clear screen ("clear" command also works)"""
    # pass
    #
    # def do_copy(self, arg):
    #     """Copy an entry: copy <path to entry> <path to new entry>"""
    #     pass
    #
    # def do_edit(self, arg):
    #     """Edit an entry: edit <path to entry|entry number>"""
    #     pass
    #
    # def do_export(self, arg):
    #     """Export entries to a new KeePass DB (export <file.kdb> [<file.key>])"""
    #     pass
    #
    # def do_find(self, arg):
    #     """Finds entries by Title"""
    #     pass

    def do_history(self, arg):
        """Prints the command history"""
        for idx, hist_line in enumerate(self._hist):
            print("{}:\t{}".format(idx, hist_line))

    # def do_icons(self, arg):
    #     """Change group or entry icons in the database"""
    #     pass
    #
    # def do_import(self, arg):
    #     """Import another KeePass DB (import <file.kdb> <path> [<file.key>])"""
    #     pass

    def do_dir(self, arg):
        return self.do_ls(arg)

    def _groups(self):
        group_list = [e.find('Name').text for e in self.current_group.findall('Group')]
        group_list.sort()
        return group_list

    @staticmethod
    def _safevalue(entry, path):
        value = entry.find(path)
        if value is None:
            return None
        elif value.text is None:
            return None
        elif value.text == '':
            return None
        else:
            return value.text

    def _title(self, entry):
        for path_choice in ["String[Key='Title']/Value", "String[Key='URL']/Value", "UUID"]:
            value = self._safevalue(entry, path_choice)
            if value is not None:
                if path_choice == "UUID":
                    return "<UUID:{}>".format(binascii.hexlify(base64.b64decode(value)).decode())
                else:
                    return value
        else:
            return ''

    def _entries(self):
        entries_list = [self._title(e) for e in self.current_group.findall('Entry')]
        entries_list.sort()
        return entries_list

    def do_ls(self, arg):
        """Lists items in the pwd or a specified path ("dir" also works)"""
        for idx, name in enumerate(self._groups()):
            print('[ ] {:3}: {}'.format(idx, name))
        for idx, name in enumerate(self._entries()):
            print('    {:3}: {}'.format(idx, name))


    # def do_mkdir(self, arg):
    #     """Create a new group (mkdir <group_name>)"""
    #     pass
    #
    # def do_mv(self, arg):
    #     """Move an item: mv <path to group|entry> <path to group>"""
    #     pass
    #
    # def do_new(self, arg):
    #     """Create a new entry: new <optional path&|title>"""
    #     pass
    #
    # def do_pwck(self, arg):
    #     """Check password quality: pwck <entry|group>"""
    #     pass
    #
    # def do_pwd(self, arg):
    #     """Print the current working directory"""
    #     pass
    #
    # def do_quit(self, arg):
    #     """Quit this program (EOF and exit also work)"""
    #     pass
    #
    # def do_rename(self, arg):
    #     """Rename a group: rename <path to group>"""
    #     pass
    #
    # def do_rm(self, arg):
    #     """Remove an entry: rm <path to entry|entry number>"""
    #     pass
    #
    # def do_rmdir(self, arg):
    #     """Delete a group (rmdir <group_name>)"""
    #     pass
    #
    # def do_save(self, arg):
    #     """Save the database to disk"""
    #     pass
    #
    # def do_saveas(self, arg):
    #     """Save to a specific filename (saveas <file.kdb> [<file.key>])"""
    #     pass

    def do_show(self, arg):
        """Show an entry: show [-f] [-a] <entry path|entry number>"""
        entries = self._entries()
        if arg in entries:
            entry = [e for e in self.current_group.findall('Entry') if self._title(e) == arg][0]
        elif re.match('\d+', arg) and int(arg) < len(entries):
            entry = [e for e in self.current_group.findall('Entry') if self._title(e) == entries[int(arg)]][0]
        else:
            print("Entry not found:", arg)
        values = {e2.find('Key').text: e2.find('Value').text for e2 in entry.findall("String")}
        value_list = ['{} = {}'.format(k, v) for k, v in values.items()]
        value_list.sort()
        print('\n'.join(value_list))


    # def do_stats(self, arg):
    #     """Prints statistics about the open KeePass file"""
    #     pass
    #
    # def do_ver(self, arg):
    #     """Print the version of this program"""
    #     pass
    #
    # def do_vers(self, arg):
    #     """Same as "ver -v" """
    #     pass
    #
    # def do_xp(self, arg):
    #     """Copy password to clipboard: xp <entry path|number>"""
    #     pass
    #
    # def do_xu(self, arg):
    #     """Copy username to clipboard: xu <entry path|number>"""
    #     pass
    #
    # def do_xw(self, arg):
    #     """Copy URL (www) to clipboard: xw <entry path|number>"""
    #     pass
    #
    # def do_xx(self, arg):
    #     """Clear the clipboard: xx"""
    #     pass

    def do_EOF(self, args):
        """Exit on system end of file character"""
        return self.do_exit(args)

    def do_exit(self, args):
        return self.do_bye(args)

    def do_bye(self, arg):
        """Exit the Keepass Shell"""
        return True

    def precmd(self, line):
        """ This method is called after the line has been input but before
            it has been interpreted. If you want to modifdy the input line
            before execution (for example, variable substitution) do it here.
        """
        self._hist += [line.strip()]
        return line

    def postcmd(self, stop, line):
        """If you want to stop the console, return something that evaluates to true.
           If you want to do some post command processing, do it here.
        """
        self.prompt = self._prompt()
        return stop

    def emptyline(self):
        """Do nothing on empty input line"""
        pass


def main():
    shell = KeePassShell()
    if len(sys.argv) == 2:
        shell.do_open(sys.argv[1])
    shell.cmdloop()


if __name__ == '__main__':
    main()
