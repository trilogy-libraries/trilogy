## Contributing

[fork]: https://github.com/github/trilogy/fork
[pr]: https://github.com/github/trilogy/compare

Hi there! We're thrilled that you'd like to contribute to this project. Your help is essential for keeping it great.

Contributions to this project are [released](https://help.github.com/articles/github-terms-of-service/#6-contributions-under-repository-license) to the public under the [project's open source license](LICENSE.md).

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## Submitting a pull request

0. [Fork][] and clone the repository
0. Build it and make sure the tests pass on your machine: `script/cibuild`. It will run both trilogy and ruby bindings suites in docker environment.
 
    To shorten the development loop you can:
     
    a) run trilogy tests locally with: `make test`  
    b) run ruby binding tests with `cd contrib/ruby`, `bundle exec rake test`. It's possible to run a test single example by passing a `TESTOPTS` environment variable like so: `TESTOPTS=-n/test_packet_size_greater_than_trilogy_max_packet_len/`.
   
0. Create a new branch: `git checkout -b my-branch-name`
0. Make your change, add tests, and make sure the tests still pass
0. Push to your fork and [submit a pull request][pr]
0. Pat yourself on the back and wait for your pull request to be reviewed and merged.

Here are a few things you can do that will increase the likelihood of your pull request being accepted:

- Follow the existing style of the code you're changing.
- Write tests.
- Keep your change as focused as possible. If there are multiple changes you would like to make that are not dependent upon each other, consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).

## Resources

- [Contributing to Open Source on GitHub](https://guides.github.com/activities/contributing-to-open-source/)
- [Using Pull Requests](https://help.github.com/articles/using-pull-requests/)
- [GitHub Help](https://help.github.com)
