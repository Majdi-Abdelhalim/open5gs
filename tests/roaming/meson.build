# Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>

# This file is part of Open5GS.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

test5gc_roaming_sources = files('''
    abts-main.c
    dereg-roaming-test.c
    mobility-roaming-test.c
    n2-handover-lbo-test.c
    n2-handover-hr-test.c
'''.split())

test5gc_roaming_exe = executable('roaming',
    sources : test5gc_roaming_sources,
    c_args : testunit_core_cc_flags,
    dependencies : libtest5gc_dep)

test('roaming',
    test5gc_roaming_exe,
    is_parallel : false,
    suite: '5gc')
