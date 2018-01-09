# objects.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all object based types. """
from . import base
from .util import get_object_type_by_name, parse_actor_and_date
from ..util import hex_to_bin
from ..compat import defenc

__all__ = ("TagObject", )


class TagObject(base.Object):

    """Non-Lightweight tag carrying additional information about an object we are pointing to."""
    type = "tag"
    __slots__ = ("object", "tag", "tagger", "tagged_date", "tagger_tz_offset", "message")

    def __init__(self, repo, binsha, object=None, tag=None,  # @ReservedAssignment
                 tagger=None, tagged_date=None, tagger_tz_offset=None, message=None):
        """Initialize a tag object with additional data

        :param repo: repository this object is located in
        :param binsha: 20 byte SHA1
        :param object: Object instance of object we are pointing to
        :param tag: name of this tag
        :param tagger: Actor identifying the tagger
        :param tagged_date: int_seconds_since_epoch
            is the DateTime of the tag creation - use time.gmtime to convert
            it into a different format
        :param tagged_tz_offset: int_seconds_west_of_utc is the timezone that the
            authored_date is in, in a format similar to time.altzone"""
        super(TagObject, self).__init__(repo, binsha)
        if object is not None:
            self.object = object
        if tag is not None:
            self.tag = tag
        if tagger is not None:
            self.tagger = tagger
        if tagged_date is not None:
            self.tagged_date = tagged_date
        if tagger_tz_offset is not None:
            self.tagger_tz_offset = tagger_tz_offset
        if message is not None:
            self.message = message

    def _set_cache_(self, attr):
        """Cache all our attributes at once"""
        if attr in TagObject.__slots__:
            ostream = self.repo.odb.stream(self.binsha)
            lines = ostream.read().decode(defenc).splitlines()

            obj, hexsha = lines[0].split(" ")       # object <hexsha> @UnusedVariable
            type_token, type_name = lines[1].split(" ")  # type <type_name> @UnusedVariable
            self.object = \
                get_object_type_by_name(type_name.encode('ascii'))(self.repo, hex_to_bin(hexsha))

            self.tag = lines[2][4:]  # tag <tag name>

            tagger_info = lines[3]  # tagger <actor> <date>
            self.tagger, self.tagged_date, self.tagger_tz_offset = parse_actor_and_date(tagger_info)

            # line 4 empty - it could mark the beginning of the next header
            # in case there really is no message, it would not exist. Otherwise
            # a newline separates header from message
            if len(lines) > 5:
                self.message = "\n".join(lines[5:])
            else:
                self.message = ''
        # END check our attributes
        else:
            super(TagObject, self)._set_cache_(attr)
