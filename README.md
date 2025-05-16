# OpenShift Login

`openshift-login` is a CLI tool designed to simplify authentication with OpenShift clusters. It integrates seamlessly with Kubernetes' kubeconfig to provide a streamlined login experience.

## Features

- Supports multiple OpenShift clusters.
- Provides an interactive login experience.


## Installation

### Download the Binary

You can download the latest release of `openshift-login` from the [GitHub Releases page](https://github.com/SRGSSR/openshift-login/releases).

For example, to download version `v0.0.7` for Linux (amd64):

```bash
curl -L -o openshift-login https://github.com/SRGSSR/openshift-login/releases/download/v0.0.7/openshift-login-linux-amd64
chmod +x openshift-login
sudo mv openshift-login /usr/local/bin/
```

### Verify Installation
Run the following command to verify the installation:

```bash
openshift-login
```

It should output `KUBERNETES_EXEC_INFO is not set` as it needs to be executed by kubectl.


## Configuring kubeconfig

To use `openshift-login` with your Kubernetes configuration, you need to add the appropriate cluster, context, and user entries to your `kubeconfig.yaml` file.

Here is an example configuration:

```yaml
apiVersion: v1
clusters:
- cluster:
    server: https://api.example-cluster.openshiftapps.com:443
  name: example-cluster
contexts:
- context:
    cluster: example-cluster
    namespace: example-namespace
    user: openshift-login
  name: example-cluster
current-context: example-cluster
kind: Config
users:
- name: openshift-login
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      args: null
      command: openshift-login
      env:
      - name: OPENSHIFT_LOGIN_LOGLEVEL
        value: warn
      interactiveMode: Always
      provideClusterInfo: true
```


### Steps to Configure

1. Replace `example-cluster` and `example-namespace` with your cluster name and namespace.
2. Ensure the `oauth_address` and `server` fields match your OpenShift cluster's API and OAuth endpoints.
3. Save the configuration to your `~/.kube/config` file or another file specified by the `KUBECONFIG` environment variable.


## Usage

Once configured, you can authenticate with your OpenShift cluster by running:

```bash
kubectl get pods
```

The `openshift-login` tool will handle the authentication process automatically.


## Contributing

Contributions are welcome! Please open an issue or submit a pull request on the [GitHub repository](https://github.com/SRGSSR/openshift-login).


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
