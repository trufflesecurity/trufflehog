# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Vincent Jacques <vincent@vincent-jacques.net>                 #
#                                                                              #
# This file is part of PyGithub.                                               #
# http://pygithub.github.io/PyGithub/v1/index.html                             #
#                                                                              #
# PyGithub is free software: you can redistribute it and/or modify it under    #
# the terms of the GNU Lesser General Public License as published by the Free  #
# Software Foundation, either version 3 of the License, or (at your option)    #
# any later version.                                                           #
#                                                                              #
# PyGithub is distributed in the hope that it will be useful, but WITHOUT ANY  #
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS    #
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more #
# details.                                                                     #
#                                                                              #
# You should have received a copy of the GNU Lesser General Public License     #
# along with PyGithub. If not, see <http://www.gnu.org/licenses/>.             #
#                                                                              #
# ##############################################################################

# #193: Line endings should be linux style

# TODO: As of Thu Aug 21 22:40:13 (BJT) Chinese Standard Time 2013
# lots of consts in this project are explict
# should realy round them up and reference them by consts
# EDIT: well, maybe :-)

# ##############################################################################
# Request Header                                                               #
# (Case sensitive)                                                             #
# ##############################################################################
REQ_IF_NONE_MATCH = "If-None-Match"
REQ_IF_MODIFIED_SINCE = "If-Modified-Since"

# ##############################################################################
# Response Header                                                              #
# (Lower Case)                                                                 #
# ##############################################################################
RES_ETAG = "etag"
RES_LAST_MODIFIED = "last-modified"
