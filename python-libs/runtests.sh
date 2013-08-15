#!/bin/bash
#
# Run the unit tests for the biokbase.Auth module and generate associated code coverage metrics
#
coverage run -m unittest discover
coverage html
