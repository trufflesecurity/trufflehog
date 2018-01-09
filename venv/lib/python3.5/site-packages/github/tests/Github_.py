# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
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

import datetime

from . import Framework

import github


class Github(Framework.TestCase):
    def testGetGists(self):
        self.assertListKeyBegin(self.g.get_gists(), lambda g: g.id, ["2729695", "2729656", "2729597", "2729584", "2729569", "2729554", "2729543", "2729537", "2729536", "2729533", "2729525", "2729522", "2729519", "2729515", "2729506", "2729487", "2729484", "2729482", "2729441", "2729432", "2729420", "2729398", "2729372", "2729371", "2729351", "2729346", "2729316", "2729304", "2729296", "2729276", "2729272", "2729265", "2729195", "2729160", "2729143", "2729127", "2729119", "2729113", "2729103", "2729069", "2729059", "2729051", "2729029", "2729027", "2729026", "2729022", "2729002", "2728985", "2728979", "2728964", "2728937", "2728933", "2728884", "2728869", "2728866", "2728855", "2728854", "2728853", "2728846", "2728825", "2728814", "2728813", "2728812", "2728805", "2728802", "2728800", "2728798", "2728797", "2728796", "2728793", "2728758", "2728754", "2728751", "2728748", "2728721", "2728716", "2728715", "2728705", "2728701", "2728699", "2728697", "2728688", "2728683", "2728677", "2728649", "2728640", "2728625", "2728620", "2728615", "2728614", "2728565", "2728564", "2728554", "2728523", "2728519", "2728511", "2728497", "2728496", "2728495", "2728487"])

    def testLegacySearchRepos(self):
        repos = self.g.legacy_search_repos("github api v3")
        self.assertListKeyBegin(repos, lambda r: r.name, ["github", "octonode", "PyGithub"])
        self.assertEqual(repos[0].full_name, "peter-murach/github")

        # Attributes retrieved from legacy API without lazy completion call
        self.assertEqual(repos[2].created_at, datetime.datetime(2012, 2, 25, 12, 53, 47))
        self.assertEqual(repos[2].name, "PyGithub")
        self.assertEqual(repos[2].watchers, 365)
        self.assertTrue(repos[2].has_downloads)
        self.assertEqual(repos[2].homepage, "http://jacquev6.github.io/PyGithub")
        self.assertEqual(repos[2].url, "/repos/jacquev6/PyGithub")
        self.assertFalse(repos[2].fork)
        self.assertTrue(repos[2].has_issues)
        self.assertFalse(repos[2].has_wiki)
        self.assertEqual(repos[2].forks, 102)
        self.assertEqual(repos[2].size, 11373)
        self.assertFalse(repos[2].private)
        self.assertEqual(repos[2].open_issues, 14)
        self.assertEqual(repos[2].pushed_at, datetime.datetime(2014, 3, 16, 17, 1, 56))
        self.assertEqual(repos[2].description, "Python library implementing the full Github API v3")
        self.assertEqual(repos[2].language, "Python")
        self.assertEqual(repos[2].owner.login, "jacquev6")
        self.assertEqual(repos[2].owner.url, "/users/jacquev6")

    def testLegacySearchReposPagination(self):
        repos = self.g.legacy_search_repos("document")
        self.assertListKeyBegin(repos, lambda r: r.name, ["git", "nimbus", "kss", "sstoolkit", "lawnchair", "appledoc", "jQ.Mobi", "ipython", "mongoengine", "ravendb", "substance", "symfony-docs", "JavaScript-Garden", "DocSets-for-iOS", "yard", "phpDocumentor2", "phpsh", "Tangle", "Ingredients", "documentjs", "xhp", "couchdb-lucene", "dox", "magento2", "javascriptmvc", "FastPdfKit", "roar", "DocumentUp", "NoRM", "jsdoc", "tagger", "mongodb-csharp", "php-github-api", "beautiful-docs", "mongodb-odm", "iodocs", "seesaw", "bcx-api", "developer.github.com", "amqp", "docsplit", "pycco", "standards-and-practices", "tidy-html5", "redis-doc", "tomdoc", "docs", "flourish", "userguide", "swagger-ui", "rfc", "Weasel-Diesel", "yuidoc", "apigen", "document-viewer", "develop.github.com", "Shanty-Mongo", "PTShowcaseViewController", "gravatar_image_tag", "api-wow-docs", "mongoid-tree", "safari-json-formatter", "mayan", "orm-documentation", "jsfiddle-docs-alpha", "core", "documentcloud", "flexible-nav", "writeCapture", "readium", "xmldocument", "Documentation-Examples", "grails-doc", "stdeb", "aws-autoscaling", "voteable_mongo", "review", "spreadsheet_on_rails", "UKSyntaxColoredTextDocument", "mandango", "bdoc", "Documentation", "documents.com", "rghost", "ticket_mule", "vendo", "khan-api", "spring-data-document-examples", "rspec_api_documentation", "axlsx", "phpdox", "documentation", "Sami", "innershiv", "doxyclean", "documents", "rvm-site", "jqapi", "documentation", "hadoopy", "VichUploaderBundle", "pdoc", "documentation", "wii-js", "oss-docs", "scala-maven-plugin", "Documents", "documenter", "behemoth", "documentation", "documentation", "propelorm.github.com", "Kobold2D", "AutoObjectDocumentation", "php-mongodb-admin", "django-mongokit", "puppet-docs", "docs", "Document", "vendorer", "symfony1-docs", "shocco", "documentation", "jog", "docs", "documentation", "documentation", "documentation", "documentation", "Documentation", "documentation", "documentation", "phpunit-documentation", "ADCtheme", "NelmioApiDocBundle", "iCloud-Singleton-CloudMe", "Documentation", "document", "document_mapper", "heroku-docs", "couchdb-odm", "documentation", "documentation", "document", "documentation", "NanoStore", "documentation", "Documentation", "documentation", "Documentation", "documentation", "document", "documentation", "documentation", "Documentation", "Documentation", "grendel", "ceylon-compiler", "mbtiles-spec", "documentation", "documents", "documents", "Documents", "Documentation", "documentation", "Documentation", "documentation", "documents", "Documentation", "documentation", "documentation", "documents", "Documentation", "documentation", "documenter", "documentation", "documents", "Documents", "documents", "documents", "documentation", "Document", "document", "rdoc", "mongoid_token", "travis-ci.github.com", "Documents", "Documents", "documents", "Document", "Documentation", "documents", "Documents", "Documentation", "documents", "documents", "documents", "documentation", "Documents", "Document", "documents", "documents", "Documentation", "Documentation", "Document", "documents", "Documents", "Documents", "Documentation", "Documents", "documents", "Documents", "document", "documents", "Documentation", "Documents", "documents", "documents", "Documents", "documents", "Documentation", "documentation", "Document", "Documents", "documents", "documents", "documents", "Documentation", "Documentation", "Documents", "Documents", "Documents", "Documenter", "document", "Documentation", "Documents", "Documents", "documentation", "documentation", "Document", "Documents", "Documentation", "Documentation", "Documents", "documents", "Documents", "document", "documentation", "Documents", "documentation", "documentation", "documentation", "Documentation", "Documents", "Documents", "documentation", "Documents", "Documents", "documentation", "documentation", "documents", "Documentation", "documents", "documentation", "Documentation", "Documents", "documentation", "documentation", "documents", "documentation", "Umbraco5Docs", "documents", "Documents", "Documentation", "documents", "document", "documents", "document", "documents", "documentation", "Documents", "documents", "document", "Documents", "Documentation", "Documentation", "documentation", "Documentation", "document", "documentation", "documents", "documents", "Documentations", "document", "documentation", "Documentation", "Document", "Documents", "Documents", "Document"])

    def testLegacySearchReposExplicitPagination(self):
        repos = self.g.legacy_search_repos("python")
        self.assertEqual([r.name for r in repos.get_page(4)], ["assetic", "cartodb", "cuisine", "gae-sessions", "geoalchemy2", "Multicorn", "wmfr-timeline", "redis-rdb-tools", "applet-workflows", "TweetBuff", "groovy-core", "StarTrekGame", "Nuevo", "Cupid", "node-sqlserver", "Magnet2Torrent", "GroundControl", "mock-django", "4bit", "mock-django", "Fabulous", "SFML", "pydicas", "flixel", "up", "mongrel2", "SimpleHTTPServerJs", "ultimos", "Archipel", "JSbooks", "nova", "nodebox", "simplehttp", "dablooms", "solarized", "landslide", "jQuery-File-Upload", "jQuery-File-Upload", "jQuery-File-Upload", "password-manager", "electrum", "twitter_nlp", "djangbone", "pyxfst", "node-gyp", "flare", "www.gittip.com", "wymeditor", "Kokobox", "MyCQ", "runwalk", "git-sweep", "HPCPythonSC2012", "sundown", "node2dm", "statirator", "fantastic-futures", "chainsaw", "itcursos-gerenciador-tarefas", "TideSDK", "genmaybot", "melpa", "ConnectedWire", "tarantool", "anserindicus_sn", "luvit", "Minecraft-Overviewer", "Iconic", "pyist.net", "wikibok", "mejorenvo-scraper", "NewsBlur", "SocketRocket", "spf13-vim", "IWantToWorkAtGloboCom", "ruby-style-guide", "aery32-refguide", "fafsite", "compsense_demo", "enaml", "mpi4py", "fi.pycon.org", "scikits-image", "scikits-image", "uni", "mako.vim", "mako.vim", "slumber", "de-composer", "nvm", "helloshopply", "Alianza", "vimfiles", "socorro-crashstats", "menu", "analytics", "elFinder", "riak_wiki", "livestreamer", "git-goggles"])

    def testLegacySearchReposWithLanguage(self):
        repos = self.g.legacy_search_repos("document", language="Python")
        self.assertListKeyBegin(repos, lambda r: r.name, ["ipython", "mongoengine", "tagger"])
        self.assertEqual(repos[0].full_name, "ipython/ipython")

    def testLegacySearchUsers(self):
        users = self.g.legacy_search_users("vincent")
        self.assertListKeyBegin(users, lambda u: u.login, ["nvie", "obra", "lusis"])

        # Attributes retrieved from legacy API without lazy completion call
        self.assertEqual(users[0].gravatar_id, "c5a7f21b46df698f3db31c37ed0cf55a")
        self.assertEqual(users[0].name, "Vincent Driessen")
        self.assertEqual(users[0].created_at, datetime.datetime(2009, 5, 12, 21, 19, 38))
        self.assertEqual(users[0].location, "Netherlands")
        self.assertEqual(users[0].followers, 310)
        self.assertEqual(users[0].public_repos, 63)
        self.assertEqual(users[0].login, "nvie")

    def testLegacySearchUsersPagination(self):
        self.assertEqual(len(list(self.g.legacy_search_users("Lucy"))), 146)

    def testLegacySearchUsersExplicitPagination(self):
        users = self.g.legacy_search_users("Lucy")
        self.assertEqual([u.login for u in users.get_page(1)], ["lucievh", "lucyim", "Lucief", "RevolverUpstairs", "seriousprogramming", "reicul", "davincidubai", "LucianaNascimentodoPrado", "lucia-huenchunao", "kraji20", "Lucywolo", "Luciel", "sunnysummer", "elush", "oprealuci", "Flika", "lsher", "datadrivenjournalism", "nill2020", "doobi", "lucilu", "deldeldel", "lucianacocca", "lucyli-sfdc", "lucysatchell", "UBM", "kolousek", "lucyzhang", "lmegia", "luisolivo", "Lucyzhen", "Luhzinha", "beautifly", "lucybm96", "BuonocoreL", "lucywilliams", "ZxOxZ", "Motwinb", "johnlucy", "Aquanimation", "alaltaieri", "lucylin", "lucychambers", "JuanSesma", "cdwwebware", "ZachWills"])

    def testLegacySearchUserByEmail(self):
        user = self.g.legacy_search_user_by_email("vincent@vincent-jacques.net")
        self.assertEqual(user.login, "jacquev6")
        self.assertEqual(user.followers, 13)

    def testGetHooks(self):
        hooks = self.g.get_hooks()
        hook = hooks[0]
        self.assertEqual(hook.name, "activecollab")
        self.assertEqual(hook.supported_events, ["push"])
        self.assertEqual(hook.events, ["push"])
        self.assertEqual(hook.schema, [["string", "url"], ["string", "token"], ["string", "project_id"], ["string", "milestone_id"], ["string", "category_id"]])

    def testGetEmojis(self):
        emojis = self.g.get_emojis()
        first = emojis.get("+1")
        self.assertEqual(first, "https://github.global.ssl.fastly.net/images/icons/emoji/+1.png?v5")

    def testGetHook(self):
        hook = self.g.get_hook("activecollab")
        self.assertEqual(hook.name, "activecollab")
        self.assertEqual(hook.supported_events, ["push"])
        self.assertEqual(hook.events, ["push"])
        self.assertEqual(hook.schema, [["string", "url"], ["string", "token"], ["string", "project_id"], ["string", "milestone_id"], ["string", "category_id"]])

    def testGetRepoFromFullName(self):
        self.assertEqual(self.g.get_repo("jacquev6/PyGithub").description, "Python library implementing the full Github API v3")

    def testGetRepoFromId(self):
        self.assertEqual(self.g.get_repo(3544490).description, "Python library implementing the full Github API v3")

    def testGetGitignoreTemplates(self):
        self.assertEqual(self.g.get_gitignore_templates(), ["Actionscript", "Android", "AppceleratorTitanium", "Autotools", "Bancha", "C", "C++", "CFWheels", "CMake", "CSharp", "CakePHP", "Clojure", "CodeIgniter", "Compass", "Concrete5", "Coq", "Delphi", "Django", "Drupal", "Erlang", "ExpressionEngine", "Finale", "ForceDotCom", "FuelPHP", "GWT", "Go", "Grails", "Haskell", "Java", "Jboss", "Jekyll", "Joomla", "Jython", "Kohana", "LaTeX", "Leiningen", "LemonStand", "Lilypond", "Lithium", "Magento", "Maven", "Node", "OCaml", "Objective-C", "Opa", "OracleForms", "Perl", "PlayFramework", "Python", "Qooxdoo", "Qt", "R", "Rails", "RhodesRhomobile", "Ruby", "Scala", "Sdcc", "SeamGen", "SketchUp", "SugarCRM", "Symfony", "Symfony2", "SymphonyCMS", "Target3001", "Tasm", "Textpattern", "TurboGears2", "Unity", "VB.Net", "Waf", "Wordpress", "Yii", "ZendFramework", "gcov", "nanoc", "opencart"])

    def testGetGitignoreTemplate(self):
        t = self.g.get_gitignore_template("Python")
        self.assertEqual(t.name, "Python")
        self.assertEqual(t.source, "*.py[cod]\n\n# C extensions\n*.so\n\n# Packages\n*.egg\n*.egg-info\ndist\nbuild\neggs\nparts\nbin\nvar\nsdist\ndevelop-eggs\n.installed.cfg\nlib\nlib64\n\n# Installer logs\npip-log.txt\n\n# Unit test / coverage reports\n.coverage\n.tox\nnosetests.xml\n\n# Translations\n*.mo\n\n# Mr Developer\n.mr.developer.cfg\n.project\n.pydevproject\n")

        t = self.g.get_gitignore_template("C++")
        self.assertEqual(t.name, "C++")
        self.assertEqual(t.source, "# Compiled Object files\n*.slo\n*.lo\n*.o\n\n# Compiled Dynamic libraries\n*.so\n*.dylib\n\n# Compiled Static libraries\n*.lai\n*.la\n*.a\n")

    def testStringOfNotSet(self):
        self.assertEqual(str(github.GithubObject.NotSet), "NotSet")

    def testGetUsers(self):
        self.assertListKeyBegin(self.g.get_users(), lambda u: u.login, ["mojombo", "defunkt", "pjhyett", "wycats", "ezmobius", "ivey", "evanphx", "vanpelt", "wayneeseguin", "brynary", "kevinclark", "technoweenie", "macournoyer", "takeo", "Caged", "topfunky", "anotherjesse", "roland", "lukas", "fanvsfan", "tomtt", "railsjitsu", "nitay", "kevwil", "KirinDave", "jamesgolick", "atmos", "errfree", "mojodna", "bmizerany", "jnewland", "joshknowles", "hornbeck", "jwhitmire", "elbowdonkey", "reinh", "timocratic", "bs", "rsanheim", "schacon", "uggedal", "bruce", "sam", "mmower", "abhay", "rabble", "benburkert", "indirect", "fearoffish", "ry", "engineyard", "jsierles", "tweibley", "peimei", "brixen", "tmornini", "outerim", "daksis", "sr", "lifo", "rsl", "imownbey", "dylanegan", "jm", "willcodeforfoo", "jvantuyl", "BrianTheCoder", "freeformz", "hassox", "automatthew", "queso", "lancecarlson", "drnic", "lukesutton", "danwrong", "hcatlin", "jfrost", "mattetti", "ctennis", "lawrencepit", "marcjeanson", "grempe", "peterc", "ministrycentered", "afarnham", "up_the_irons", "evilchelu", "heavysixer", "brosner", "danielmorrison", "danielharan", "kvnsmth", "collectiveidea", "canadaduane", "nate", "dstrelau", "sunny", "dkubb", "jnicklas", "richcollins", "simonjefford"])

    def testGetUsersSince(self):
        self.assertListKeyBegin(self.g.get_users(since=1000), lambda u: u.login, ["sbecker"])

    def testGetRepos(self):
        self.assertListKeyBegin(self.g.get_repos(), lambda r: r.name, ["grit", "merb-core", "rubinius", "god", "jsawesome", "jspec", "exception_logger", "ambition"])

    def testGetReposSince(self):
        self.assertListKeyBegin(self.g.get_repos(since=1000), lambda r: r.name, ["jquery-humanize-messages-plugin", "4slicer", "fixture-scenarios", "mongrel_proctitle", "rails-plugins"])
