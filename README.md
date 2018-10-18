# A dnsjava mirror hosted at github

This repository contains a github mirror of the dnsjava svn repository
located at http://sourceforge.net/p/dnsjava/code/HEAD/tree/

On top of the upstream project I maintain this README.md file and
a maven build pom.xml build file. The aim is to have a straightforward
way to build and deploy arbitrary versions of the dnsjava library as
maven artifacts and make them available as maven managed dependencies.

This repository is not at this time endorsed by Brian Wellington, the
maintainer of the upstream dnsjava project. There is, however,
nothing stopping that from happening. Brian, if you are listening and
are interested in taking over this effort, just drop me a line.

## Reporting issues with pom.xml

Feel free to open an issue on github, or even better, submit a pull
request resolving your issue.

## Reporting issues and providing patches to the upstream project

This should be done using the dnsjava sourceforge project located
at http://sourceforge.net/projects/dnsjava/. For your code tracking
convenience, the commits to upstream trunk are also available in
the branch named `upstream`. 

## Details on how this repository is maintained

This repository is populated using the git-svn tool, initially
by running the following command:
`git svn clone --stdlayout http://svn.code.sf.net/p/dnsjava/code`

I then manually pushed the master branch onto the branch `upstream`
and copied the pom.xml file from
https://issues.sonatype.org/browse/OSSRH-1305
with some updates to the master branch. 
