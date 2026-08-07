FROM alpine:latest
ENV CONFIG='https://raw.githubusercontent.com/ircfspace/warpsub/main/export/warp#WARP%20(IRCF)'
ENV VERSION=v4.1.0
WORKDIR /hiddify
RUN apk add  curl tar gzip libc6-compat # iptables ip6tables

RUN echo "architecture: $(apk --print-arch)" && \    
    case "$(apk --print-arch)" in \
            x86_64) ARCH=amd64 ;; \
            i386|x86) ARCH=386 ;; \
            aarch64) ARCH=arm64 ;; \
            armv7) ARCH=armv7 ;; \
            armv6|armhf) ARCH=armv6 ;; \
            armv5) ARCH=armv5 ;; \
            s390x) ARCH=s390x ;; \
            *) echo "Unsupported architecture: $(apk --print-arch) $(uname -m)" && exit 1 ;; \
        esac && \
        echo "Downloading https://github.com/ne-tort/pathology-core/releases/download/${VERSION}/pathology-core-linux-$ARCH.tar.gz" && \
        curl -L -o pathology-core.tar.gz https://github.com/ne-tort/pathology-core/releases/download/${VERSION}/pathology-core-linux-$ARCH.tar.gz && \
        tar -xzf pathology-core.tar.gz && rm pathology-core.tar.gz
COPY pathology.sh .
RUN chmod +x pathology.sh

EXPOSE 12334
EXPOSE 12335
EXPOSE 16756
EXPOSE 12335
EXPOSE 12337


ENTRYPOINT [ "/hiddify/pathology.sh" ]
