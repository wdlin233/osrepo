# rCore-Camp-Code-2025S

### Code

- [Soure Code of labs for 2025S](https://github.com/LearningOS/rCore-Camp-Code-2025S)

### Documents

- Concise Manual: [rCore-Camp-Guide-2025S](https://LearningOS.github.io/rCore-Camp-Guide-2025S/)
- Detail Book [rCore-Tutorial-Book-v3](https://rcore-os.github.io/rCore-Tutorial-Book-v3/)

### OS API docs

- [ch1](https://learningos.github.io/rCore-Camp-Code-2025S/ch1/os/index.html) [ch2](https://learningos.github.io/rCore-Camp-Code-2025S/ch2/os/index.html) [ch3](https://learningos.github.io/rCore-Camp-Code-2025S/ch3/os/index.html) [ch4](https://learningos.github.io/rCore-Camp-Code-2025S/ch4/os/index.html)
- [ch5](https://learningos.github.io/rCore-Camp-Code-2025S/ch5/os/index.html) [ch6](https://learningos.github.io/rCore-Camp-Code-2025S/ch6/os/index.html) [ch7](https://learningos.github.io/rCore-Camp-Code-2025S/ch7/os/index.html) [ch8](https://learningos.github.io/rCore-Camp-Code-2025S/ch8/os/index.html)

### Related Resources

- [Learning Resource](https://github.com/LearningOS/rust-based-os-comp2022/blob/main/relatedinfo.md)

### Build & Run

Replace `<YourName>` with your github ID, and replace `<Number>` with the chapter ID.

Notice: `<Number>` is chosen from `[1,2,3,4,5,6,7,8]`

```bash
# 
$ git clone git@github.com:LearningOS/2025s-rcore-<YourName>
$ cd 2025s-rcore-<YourName>
$ git clone git@github.com:LearningOS/rCore-Tutorial-Test-2025S user
$ git checkout ch<Number>
$ cd os
$ make run
```

### Grading

Replace `<YourName>` with your github ID, and replace `<Number>` with the chapter ID.

Notice: `<Number>` is chosen from `[3,4,5,6,8]`

```bash
# Replace <YourName> with your github ID 
$ git clone git@github.com:LearningOS/2025s-rcore-<YourName>
$ cd 2025s-rcore-<YourName>
$ rm -rf ci-user
$ git clone git@github.com:LearningOS/rCore-Tutorial-Checker-2025S ci-user
$ git clone git@github.com:LearningOS/rCore-Tutorial-Test-2025S ci-user/user
$ git checkout ch<Number>
$ cd ci-user
$ make test CHAPTER=<Number>
```


# SubsToKernel
