# PAMMS
Privacy-Assured Messaging Measurement System

## Usage
Build the docker conatiner
```
docker build . -t pamms
```

Then enter the container 
```
docker run -it --rm pamms
```

Then compile each cline using the make in each project.

Use the helper script `eval.sh`, which will use Intel PIN on the host machine and measure instructions. 

## Code References
- Riposte
- Sabre
- Express

Code may be highly modified depending on the needs for compilation. To understand differences applied git diff
this code with the original code. 

## Results 
Instructions for Client Writing:

- Riposte: 13252840326
- Sabre:   3589677627
- Express: 643565609
