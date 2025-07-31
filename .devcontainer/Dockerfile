FROM ubuntu@sha256:79efa276fdefa2ee3911db29b0608f8c0561c347ec3f4d4139980d43b168d991

# Update the package database and install required tools
RUN apt-get update
RUN apt-get install --fix-missing -y python3 python3-pip pipx git less vim sudo cmake make g++-15 libjemalloc-dev clang-format clangd-19

# Update  gcc/g++ version to the latest ones
RUN ln -fs /usr/bin/g++-15 /usr/bin/g++
RUN ln -fs /usr/bin/gcc-15 /usr/bin/gcc

ARG USER=dev
ARG USER_GID=1001
ARG USER_UID=1001

# Create a non-root user 'dev'
RUN useradd -ms /bin/bash dev \
    && echo "dev ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/dev \
    && chmod 0440 /etc/sudoers.d/dev

# Switch to the 'dev' user
USER dev

RUN git config --global core.editor code

# Install conan through pipx
RUN pipx install conan
RUN pipx ensurepath

# Copy conan profile
COPY default /home/dev/.conan2/profiles/default
RUN sudo chown -R dev:dev /home/dev/.conan2
RUN sudo chmod 666 /home/dev/.conan2/profiles/default

# Set the default command
CMD ["/bin/bash"]
