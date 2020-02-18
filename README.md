# Prowler JSON Parser

A simple Go app that will parse the `-M json` output that prowler provides into something useful.

Note this is more of a go exercise than some sort of authoritative project for using Prowler. Importantly, it includes code that removes the banner and filters out non-failures from the results, both of which can be achieved by running Prowler with different command flags.

I built this both to learn more Go, and because Prowler takes a good amount of time to run through and I couldn't be bothered running it again once I figured out how to use the tool better :D