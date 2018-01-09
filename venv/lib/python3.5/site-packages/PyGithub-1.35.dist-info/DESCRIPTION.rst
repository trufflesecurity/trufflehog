(Very short) Tutorial
=====================

First create a Github instance::

    from github import Github

    g = Github("user", "password")

Then play with your Github objects::

    for repo in g.get_user().get_repos():
        print repo.name
        repo.edit(has_wiki=False)

You can also create a Github instance with an OAuth token::

    g = Github(token)

Or without authentication::

    g = Github()

Reference documentation
=======================

See http://pygithub.github.io/PyGithub/v1/index.html

