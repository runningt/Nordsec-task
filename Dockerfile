ARG IMAGE_VARIANT=slim-buster
ARG OPENJDK_VERSION=8
ARG PYTHON_VERSION=3.10

FROM python:${PYTHON_VERSION}-${IMAGE_VARIANT} AS python310
FROM openjdk:${OPENJDK_VERSION}-${IMAGE_VARIANT}

COPY --from=py310 / /

ARG PYSPARK_VERSION=3.2.0
RUN pip --no-cache-dir install pyspark==${PYSPARK_VERSION} jupyterlab notebook ipython

ENTRYPOINT ["ipython"]
