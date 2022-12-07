# `linear` branch

This branch contains the **most modern version of the Riposte code**, which is used in the variant of Riposte that appears in Henry Corrigan-Gibbs' [PhD dissertation](https://purl.stanford.edu/nm483fv2043). This is the cleanest and fastest variant of the scheme and you should use this version unless you have a good reason to prefer the historical ones from the original Riposte paper.



An explanation of the branches in this repository is [here](https://bitbucket.org/henrycg/riposte/).


## How to build


1. Make sure that you have `go` installed:
```
go version
```

2. Clone the repository:
```
git clone https://bitbucket.org/henrycg/riposte/
```

3. Build the `client` and `server` binaries:
```
cd riposte
cd client 
go build
cd ..
cd server
go build
cd ..
```

4. Now you should be able to run 
```
server/server -help
client/client -help
```
to run the client and server and see the command-line options.
