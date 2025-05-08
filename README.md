<a name="readme-top"></a>

<!-- PROJECT DETAILS -->
<div align="center">

  <h1 align="center">WHOactuallyIS?</h1>

  <p align="center">
    A <a href="https://systronlab.github.io"><strong>SYSTRON Lab</strong></a> tool
    <br />
    from the <a href="https://www.cs.york.ac.uk/"><strong>Department of Computer Science</strong></a> at the University of York
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-tool">About the tool</a></li>
    <li><a href="#getting-started">Getting started</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE TOOL -->
## About the tool

This tool returns information about the owners and users of Internet resources, rather than simply registration information. It works by analysing available information from registries and DNS records to make inferences about likely users and owners.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting started

> WHOactuallyIS does not currently support Windows because of a dependency on the `dns-crawler` Python package.

**Install Python prerequisites**
```sh
$ pip install -r requirements.txt
```

**Lookup a resource from commandline**
```sh
$ python wai.py -t 8.8.8.8
```

**Use WHOactuallyIS in a program**
```python
import whoactuallyis

result = whoactuallyis.lookup('8.8.8.8')
print(whoactuallyis.show_final_name(result))
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTACT -->
## Contact

**Josh Levett**: [@Levett_Josh](https://twitter.com/Levett_Josh) / joshua.levett (at) york.ac.uk


<p align="right">(<a href="#readme-top">back to top</a>)</p>