#  Observability on Kubernetes with Cillium and Hubble 

This lab demonstrates Cilium and Hubble's observability capabilities using a simple 3-tier web application on Kind.

## Understanding Network Observability

### What is Network Observability?

**Network observability** is the ability to understand the internal state of your network by examining the data it produces. In Kubernetes environments, this means having complete visibility into:

- **Who is talking to whom** (service-to-service communication)
- **What protocols are being used** (HTTP, gRPC, TCP, UDP, DNS)
- **How much traffic flows** between services (bandwidth, request rates)
- **When connections succeed or fail** (latency, errors, timeouts)
- **Why traffic is blocked or allowed** (security policy enforcement)

### The Three Pillars of Observability

1. **Metrics** - Quantitative measurements (request count, latency, error rates)
2. **Logs** - Discrete events with context (connection attempts, policy violations)
3. **Traces** - Request flows across multiple services (distributed tracing)

Network observability adds a fourth pillar:
4. **Flows** - Real-time network traffic patterns and relationships

### Why Traditional K8s Lacks Network Observability

Standard Kubernetes networking provides:
- ❌ **No visibility** into pod-to-pod communication
- ❌ **No real-time monitoring** of network flows
- ❌ **No protocol awareness** beyond basic IP/port
- ❌ **No security policy insights** 
- ❌ **Limited troubleshooting** capabilities

You typically rely on:
- Application logs (incomplete picture)
- kubectl describe (static information)
- Network tools like tcpdump (manual, reactive)
- Guesswork when networking issues occur

### How Cilium + Hubble Achieves Network Observability

#### Cilium: The Data Plane
**Cilium** uses **eBPF (extended Berkeley Packet Filter)** technology to:
- **Intercept every network packet** at the kernel level
- **Extract metadata** from L3-L7 protocols (IP, TCP, HTTP, gRPC, Kafka, etc.)
- **Apply security policies** based on workload identity
- **Collect flow information** without impacting application performance

#### Hubble: The Observability Layer
**Hubble** sits on top of Cilium and provides:
- **Real-time flow visibility** - See network traffic as it happens
- **Protocol-aware insights** - Understand HTTP requests, DNS queries, etc.
- **Service relationship mapping** - Automatically discover service dependencies
- **Security policy monitoring** - Watch policies allow/deny traffic in real-time
- **Historical analysis** - Store and query network flow data
- **Visual representation** - Web UI with service maps and flow diagrams

#### The Magic: eBPF in the Kernel
```
┌─────────────────┐    ┌─────────────────┐
│   Application   │    │   Application   │
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│   Container     │    │   Container     │
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────┐
│           Linux Kernel                  │
│  ┌─────────────────────────────────┐    │
│  │        eBPF Programs            │    │ ← Cilium hooks here
│  │    (Cilium + Hubble)            │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
         │
         ▼
    Network Interface
```

#### Key Observability Features You'll Experience:

1. **Flow Monitoring**
   - Every network connection tracked
   - Source → Destination mapping
   - Protocol identification (HTTP, DNS, TCP, etc.)
   - Real-time and historical views

2. **Service Discovery**
   - Automatic service relationship mapping
   - Visual service topology
   - Dependency analysis

3. **Security Insights**
   - Policy enforcement visualization
   - Allowed vs denied traffic
   - Security audit trails

4. **Performance Monitoring**
   - Latency measurements
   - Throughput analysis
   - Error rate tracking

5. **Troubleshooting Capabilities**
   - Live packet analysis
   - Connection failure diagnosis
   - DNS resolution monitoring

### What You'll Learn in This Lab

By the end of this lab, you'll understand how to:
- **See every network flow** in your cluster in real-time
- **Identify service dependencies** automatically
- **Monitor security policies** and their effects
- **Debug network issues** with precision
- **Analyze application performance** from a network perspective

This represents a fundamental shift from **reactive troubleshooting** to **proactive monitoring** and **predictive insights** in Kubernetes networking.

## Prerequisites

- Ubuntu 22.04 LTS
- Docker installed and running
- 4GB RAM available

## Lab Architecture

Simple web application with:
- **Frontend**: Nginx web server
- **Backend**: Simple API service  
- **Database**: Redis for data storage

## Why Cilium Instead of Default CNI (kindnet)?

| Feature | kindnet (Default) | Cilium |
|---------|-------------------|---------|
| **Networking** | Bridge + iptables | eBPF kernel bypass |
| **Performance** | Linear degradation with scale | Constant performance |
| **Security** | Basic NetworkPolicies (L3/L4) | Identity-based + L7 policies |
| **Observability** | None built-in | Real-time flow visibility |
| **Load Balancing** | kube-proxy (iptables) | eBPF-based, DSR capable |
| **Encryption** | None | Transparent WireGuard/IPSec |
| **Service Mesh** | Requires separate solution | Built-in capabilities |
| **Troubleshooting** | kubectl logs + guesswork | Live network flow analysis |

## Step 1: Install Required Tools

```bash
# Install Kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Install Cilium CLI
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/master/stable.txt)
curl -L --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz
sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz

# Install Hubble CLI
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -L --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz
sudo tar xzvfC hubble-linux-amd64.tar.gz /usr/local/bin
rm hubble-linux-amd64.tar.gz
```

## Step 2: Create Kind Cluster

```bash
# Create cluster without CNI
cat > kind-config.yaml << EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 80
    hostPort: 8080
- role: worker
networking:
  disableDefaultCNI: true
EOF

# Create the cluster
kind create cluster --config=kind-config.yaml

# Verify cluster
kubectl get nodes
```

## Step 3: Install Cilium with Hubble

```bash
# Install Cilium with Hubble enabled
cilium install \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"

# Wait for Cilium to be ready
cilium status --wait

# Verify installation
cilium connectivity test
```

## Step 4: Deploy Simple 3-Tier Application

```bash
# Create namespace
kubectl create namespace demo

# Deploy Redis database
kubectl apply -f - << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
        tier: database
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: demo
spec:
  selector:
    app: redis
  ports:
  - port: 6379
EOF

# Deploy Backend API
kubectl apply -f - << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: demo
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
        tier: backend
    spec:
      containers:
      - name: backend
        image: hashicorp/http-echo:latest
        args:
        - -text=Backend API v1.0 - Connected to Redis
        - -listen=:8080
        ports:
        - containerPort: 8080
        env:
        - name: REDIS_HOST
          value: redis
---
apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: demo
spec:
  selector:
    app: backend
  ports:
  - port: 8080
EOF

# Deploy Frontend
kubectl apply -f - << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
        tier: frontend
    spec:
      containers:
      - name: python-server
        image: python:3.9-alpine
        ports:
        - containerPort: 8000
        command: ["sh", "-c"]
        args:
        - |
          pip install requests
          cat > /tmp/server.py << 'PYTHON'
          import http.server
          import socketserver
          import urllib.parse
          import requests
          import json
          
          class ProxyHandler(http.server.SimpleHTTPRequestHandler):
              def do_GET(self):
                  if self.path == '/api':
                      try:
                          response = requests.get('http://backend:8080')
                          self.send_response(200)
                          self.send_header('Content-type', 'text/plain')
                          self.send_header('Access-Control-Allow-Origin', '*')
                          self.end_headers()
                          self.wfile.write(response.text.encode())
                      except Exception as e:
                          self.send_response(500)
                          self.send_header('Content-type', 'text/plain')
                          self.end_headers()
                          self.wfile.write(f'Error: {str(e)}'.encode())
                  else:
                      # Serve the HTML page
                      self.send_response(200)
                      self.send_header('Content-type', 'text/html')
                      self.end_headers()
                      html = '''
                      <!DOCTYPE html>
                      <html>
                      <head>
                          <title>Cilium Demo</title>
                          <style>
                              body { font-family: Arial, sans-serif; margin: 40px; }
                              .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 10px; }
                              #result { margin-top: 20px; padding: 20px; background: #f0f0f0; border-radius: 8px; }
                          </style>
                      </head>
                      <body>
                          <h1>Cilium & Hubble Demo</h1>
                          <p>Network observability demonstration</p>
                          
                          <button class="btn" onclick="testAPI()">Call Backend API</button>
                          <button class="btn" onclick="loadTest()">Generate Load (10 requests)</button>
                          
                          <div id="result">Click buttons to generate network traffic!</div>
                          
                          <script>
                              function testAPI() {
                                  fetch('/api')
                                      .then(response => response.text())
                                      .then(data => {
                                          document.getElementById('result').innerHTML = 'SUCCESS - Backend Response: ' + data;
                                      })
                                      .catch(error => {
                                          document.getElementById('result').innerHTML = 'ERROR: ' + error;
                                      });
                              }
                              
                              function loadTest() {
                                  document.getElementById('result').innerHTML = 'Generating 10 requests...';
                                  let completed = 0;
                                  
                                  for (let i = 0; i < 10; i++) {
                                      fetch('/api')
                                          .then(response => response.text())
                                          .then(() => {
                                              completed++;
                                              document.getElementById('result').innerHTML = 
                                                  'Progress: ' + completed + '/10 requests completed';
                                              if (completed === 10) {
                                                  document.getElementById('result').innerHTML = 
                                                      'COMPLETED! 10 requests sent. Check Hubble to see the network flows!';
                                              }
                                          })
                                          .catch(error => {
                                              completed++;
                                              if (completed === 10) {
                                                  document.getElementById('result').innerHTML = 'Some requests completed with errors';
                                              }
                                          });
                                  }
                              }
                          </script>
                      </body>
                      </html>
                      '''
                      self.wfile.write(html.encode())
          
          with socketserver.TCPServer(("", 8000), ProxyHandler) as httpd:
              print("Server running on port 8000")
              httpd.serve_forever()
          PYTHON
          python /tmp/server.py
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: demo
spec:
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
EOF

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=redis -n demo --timeout=300s
kubectl wait --for=condition=ready pod -l app=backend -n demo --timeout=300s
kubectl wait --for=condition=ready pod -l app=frontend -n demo --timeout=300s

echo "✅ Application deployed successfully!"
```

## Step 5: Access the Application

```bash
# Forward port to access the app
kubectl port-forward -n demo svc/frontend 8080:80 &

echo "🌐 Application available at: http://localhost:8080"
echo "Click the buttons to generate traffic for observability"
```

## Step 6: Explore Hubble Observability

### Enable Hubble Port Forwarding

```bash
# Forward Hubble Relay port
cilium hubble port-forward &

# Forward Hubble UI port
cilium hubble ui &

echo "🔍 Hubble UI available at: http://localhost:12000"
```

### Command Line Observability

```bash
# View live network flows
hubble observe

# View flows for specific namespace
hubble observe --namespace demo

# View HTTP traffic
hubble observe --protocol http

# View flows between services
hubble observe --from-service demo/frontend --to-service demo/backend

# View DNS requests
hubble observe --protocol dns

# View dropped packets
hubble observe --verdict DROPPED

# View traffic with specific labels
hubble observe --label app=backend

# Get flow statistics
hubble observe --output compact
```

## Step 7: Generate Traffic and Observe

```bash
# Generate some traffic
curl http://localhost:8080
curl http://localhost:8080/api

# In another terminal, watch the flows
hubble observe --follow

# Generate load and observe patterns
for i in {1..20}; do
    curl -s http://localhost:8080/api > /dev/null
    echo "Request $i sent"
    sleep 1
done
```

## Step 8: Understanding Cilium's Default Security Model

### Cilium's Security-First Approach

Unlike traditional Kubernetes networking, Cilium implements a **"default deny"** security model with identity-based policies:

```bash
# Check current security status
cilium status | grep -A 5 "Security"

# View default policy enforcement
cilium config | grep -E "policy-enforcement|enable-policy"
```

### Demonstration 1: Default Allow Behavior (Initial State)

```bash
# First, let's see the current "allow all" behavior
echo "🔍 Testing connectivity between all services..."

# Frontend to Backend (should work)
kubectl exec -n demo deployment/frontend -- curl -s backend:8080
echo "✅ Frontend → Backend: Success"

# Create a test pod to simulate unauthorized access
kubectl run unauthorized-pod -n demo --image=curlimages/curl --rm -i --tty -- sh -c "
echo 'Testing unauthorized access:'
curl -s backend:8080 && echo '✅ Unauthorized → Backend: Success (No security yet)'
curl -s redis:6379 && echo '✅ Unauthorized → Redis: Success (No security yet)'
"
```

### Demonstration 2: Security Policy Denied Request Demo

Let's create a practical demonstration where a request is denied by a security policy:

```bash
# Create a "malicious" pod that will be denied access
kubectl apply -f - << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: malicious-pod
  namespace: demo
  labels:
    app: malicious-pod
    security: untrusted
spec:
  replicas: 1
  selector:
    matchLabels:
      app: malicious-pod
  template:
    metadata:
      labels:
        app: malicious-pod
        security: untrusted
        tier: attacker
    spec:
      containers:
      - name: attacker
        image: curlimages/curl
        command: ["sleep", "3600"]
---
apiVersion: v1
kind: Service
metadata:
  name: malicious-pod
  namespace: demo
  labels:
    app: malicious-pod
    security: untrusted
spec:
  selector:
    app: malicious-pod
  ports:
  - port: 80
EOF

# Wait for the malicious pod to be ready
kubectl wait --for=condition=ready pod -l app=malicious-pod -n demo --timeout=60s

# Test that the malicious pod can currently access services (before policy)
echo "🔓 Before security policy - malicious pod can access backend:"
kubectl exec -n demo deployment/malicious-pod -- curl -s --connect-timeout 5 backend:8080
```

### Demonstration 3: Implementing Zero-Trust Security with Specific Deny Rules

```bash
# Start Hubble observation to see denied traffic
echo "🔍 Starting Hubble observation for security events..."
cilium hubble port-forward &
hubble observe --verdict DENIED --follow &

# Create a security policy that denies access from untrusted sources
kubectl apply -f - << 'EOF'
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend-security-policy
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
  # Explicitly deny access from untrusted sources
  - fromEndpoints:
    - matchLabels:
        security: untrusted
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
    icmps:
    - {}
    # This rule will be overridden by the deny-all at the end
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: redis-security-policy
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: redis
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: backend
    toPorts:
    - ports:
      - port: "6379"
        protocol: TCP
EOF

# Wait for policies to take effect
echo "⏳ Waiting for security policies to take effect..."
sleep 10

# Test denied access
echo "🚫 After security policy - testing denied access:"
kubectl exec -n demo deployment/malicious-pod -- timeout 5 curl -v backend:8080 2>&1 || echo "❌ DENIED: Malicious pod blocked by security policy"

# Test that legitimate traffic still works
echo "✅ Testing legitimate access still works:"
kubectl exec -n demo deployment/frontend -- curl -s backend:8080

# Show the policy in action via web interface
echo "🌐 Test via web interface - click 'Call Backend API' at http://localhost:8080"
echo "   This should work (frontend → backend allowed)"
```

### Demonstration 4: Layer 7 Security Policy Demo

```bash
# Create a more sophisticated L7 policy that denies specific HTTP methods
kubectl apply -f - << 'EOF'
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend-l7-security
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: "GET"
          path: "/"
        # POST, PUT, DELETE are implicitly denied
EOF

# Test that GET requests work
echo "✅ Testing allowed GET request:"
kubectl exec -n demo deployment/frontend -- curl -s -X GET backend:8080

# Test that other HTTP methods are denied
echo "🚫 Testing denied POST request:"
kubectl exec -n demo deployment/frontend -- timeout 5 curl -s -X POST backend:8080 2>&1 || echo "❌ DENIED: POST method blocked by L7 policy"

echo "🚫 Testing denied PUT request:"
kubectl exec -n demo deployment/frontend -- timeout 5 curl -s -X PUT backend:8080 2>&1 || echo "❌ DENIED: PUT method blocked by L7 policy"
```

### Demonstration 5: DNS Security Policy Demo

```bash
# Create a DNS security policy that restricts DNS queries
kubectl apply -f - << 'EOF'
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: frontend-dns-security
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: frontend
  egress:
  - toEndpoints:
    - matchLabels:
        app: backend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
  - toEntities:
    - "kube-apiserver"
  - toEntities:
    - "host"
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
      rules:
        dns:
        - matchPattern: "backend.demo.svc.cluster.local"
        - matchPattern: "redis.demo.svc.cluster.local"
        # External DNS queries are implicitly denied
EOF

# Test allowed DNS query
echo "✅ Testing allowed DNS query:"
kubectl exec -n demo deployment/frontend -- nslookup backend.demo.svc.cluster.local

# Test denied external DNS query
echo "🚫 Testing denied external DNS query:"
kubectl exec -n demo deployment/frontend -- timeout 5 nslookup google.com 2>&1 || echo "❌ DENIED: External DNS query blocked by DNS policy"
```

### Demonstration 6: Real-Time Security Monitoring

```bash
# Create a comprehensive test that shows multiple denials
echo "🎯 Running comprehensive security test - watch Hubble for denied requests..."

# Generate denied traffic patterns
kubectl exec -n demo deployment/malicious-pod -- sh -c "
  echo 'Generating denied traffic patterns...'
  for i in \$(seq 1 5); do
    echo 'Attempt \$i: Trying to access backend (should be denied)'
    timeout 3 curl -s backend:8080 || echo 'Access denied as expected'
    sleep 1
  done
" &

# Generate denied HTTP methods
kubectl exec -n demo deployment/frontend -- sh -c "
  echo 'Testing denied HTTP methods...'
  timeout 3 curl -s -X DELETE backend:8080 || echo 'DELETE denied as expected'
  timeout 3 curl -s -X PUT backend:8080 || echo 'PUT denied as expected'
  timeout 3 curl -s -X PATCH backend:8080 || echo 'PATCH denied as expected'
" &

# Generate denied DNS queries
kubectl exec -n demo deployment/frontend -- sh -c "
  echo 'Testing denied DNS queries...'
  timeout 3 nslookup malicious-site.com || echo 'External DNS denied as expected'
  timeout 3 nslookup attacker.net || echo 'External DNS denied as expected'
" &

echo "🔍 Check Hubble UI at http://localhost:12000 to see denied flows in real-time"
echo "🖥️  Also watch the terminal output for denied traffic patterns"

# Wait for background jobs to complete
wait

# Show summary of security policies
echo "📋 Security policies applied:"
kubectl get ciliumnetworkpolicies -n demo
```

### Demonstration 7: Policy Effectiveness Verification

```bash
# Verify that security policies are working as expected
echo "🔍 Security Policy Effectiveness Report:"

# Test legitimate traffic (should work)
echo "✅ Legitimate traffic tests:"
kubectl exec -n demo deployment/frontend -- curl -s backend:8080 | head -1
kubectl exec -n demo deployment/backend -- nc -z redis 6379 && echo "Backend can reach Redis"

# Test blocked traffic (should fail)
echo "🚫 Blocked traffic tests:"
kubectl exec -n demo deployment/malicious-pod -- timeout 3 curl backend:8080 2>&1 | grep -q "curl" && echo "❌ Malicious pod blocked from backend" || echo "❌ Malicious pod blocked from backend"

# Show denied flows in Hubble
echo "📊 Recent denied flows:"
hubble observe --verdict DENIED --namespace demo --last 10

# Show policy enforcement statistics
echo "📈 Policy enforcement summary:"
hubble observe --namespace demo --last 50 --output json | jq -r '.verdict' | sort | uniq -c
```

### Demonstration 2: Implementing Zero-Trust Security

```bash
# Enable default deny policy enforcement
echo "🔒 Implementing Zero-Trust Security..."

# Create a default deny policy for the entire namespace
kubectl apply -f - << EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: default-deny-all
  namespace: demo
spec:
  endpointSelector: {}
  ingress: []
  egress: []
EOF

# Wait a moment for policy to take effect
sleep 5

echo "🚫 All traffic is now blocked by default!"
```

### Demonstration 3: Testing Zero-Trust Enforcement

```bash
# Test that everything is now blocked
echo "Testing blocked connectivity..."

# This should fail now
kubectl run test-blocked --image=curlimages/curl --rm -i --tty -- sh -c "
echo 'Testing after zero-trust policy:'
timeout 5 curl backend.demo:8080 || echo '🚫 Unauthorized → Backend: BLOCKED'
timeout 5 curl redis.demo:6379 || echo '🚫 Unauthorized → Redis: BLOCKED'
"

# Even legitimate traffic should be blocked
kubectl exec -n demo deployment/frontend -- timeout 5 curl backend:8080 || echo "🚫 Frontend → Backend: BLOCKED (even legitimate traffic)"

# Watch the denied flows in real-time
echo "🔍 Observing denied traffic..."
timeout 10 hubble observe --verdict DENIED --namespace demo
```

### Demonstration 4: Implementing Precise Allow Policies

```bash
# Now create precise policies that allow only necessary communication
echo "🔧 Creating precise security policies..."

# Policy 1: Allow frontend to backend communication
kubectl apply -f - << EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
EOF

# Policy 2: Allow backend to redis communication
kubectl apply -f - << EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-backend-to-redis
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: redis
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: backend
    toPorts:
    - ports:
      - port: "6379"
        protocol: TCP
EOF

# Policy 3: Allow egress for frontend (to reach backend)
kubectl apply -f - << EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-frontend-egress
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: frontend
  egress:
  - toEndpoints:
    - matchLabels:
        app: backend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
  - toEntities:
    - "kube-apiserver"
  - toEntities:
    - "host"
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
EOF

# Policy 4: Allow egress for backend (to reach redis)
kubectl apply -f - << EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-backend-egress
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: backend
  egress:
  - toEndpoints:
    - matchLabels:
        app: redis
    toPorts:
    - ports:
      - port: "6379"
        protocol: TCP
  - toEntities:
    - "kube-apiserver"
  - toEntities:
    - "host"
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
EOF

sleep 5
echo " Precise security policies applied!"
```

### Demonstration 5: Testing Secure Communication

```bash
# Test that legitimate traffic now works
echo "🧪 Testing legitimate communication..."

# This should work now
kubectl exec -n demo deployment/frontend -- curl -s backend:8080
echo " Frontend → Backend: Allowed by policy"

# Test unauthorized access (should still be blocked)
kubectl run test-unauthorized --image=curlimages/curl --rm -i --tty -- sh -c "
echo 'Testing unauthorized access after policies:'
timeout 5 curl backend.demo:8080 || echo '🚫 Unauthorized → Backend: Still BLOCKED'
timeout 5 curl redis.demo:6379 || echo '🚫 Unauthorized → Redis: Still BLOCKED'
"

# Test your web application
echo "🌐 Test the web application at http://localhost:8080"
echo "The 'Call Backend API' button should work, demonstrating secure communication"
```

### Demonstration 6: Advanced Security Features

```bash
# Layer 7 (HTTP) Security Policies
echo "🔒 Implementing Layer 7 HTTP security..."

kubectl apply -f - << EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: l7-http-policy
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: "GET"
          path: "/"
        - method: "POST"
          path: "/api"
EOF

echo "✅ Layer 7 HTTP policy applied - only GET / and POST /api allowed"

# DNS Security
kubectl apply -f - << EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: dns-security
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: frontend
  egress:
  - toEntities:
    - "host"
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
      rules:
        dns:
        - matchPattern: "backend.demo.svc.cluster.local"
        - matchPattern: "kubernetes.default.svc.cluster.local"
EOF

echo "✅ DNS security policy applied - only specific DNS queries allowed"
```

### Service Map and Metrics

```bash
# View service dependencies
hubble observe --namespace demo --output json | jq '.source.labels[], .destination.labels[]'

# View metrics
hubble metrics list
hubble metrics get flow

# View specific service metrics
hubble observe --namespace demo --from-service demo/frontend --to-service demo/backend --output json
```

## Step 9: Observing Security in Action

### Real-time Security Monitoring

```bash
# Monitor security policy enforcement in real-time
echo "🔍 Monitoring security policies..."

# Terminal 1: Watch all denied traffic
hubble observe --verdict DENIED --follow &

# Terminal 2: Watch allowed traffic  
hubble observe --verdict ALLOWED --namespace demo --follow &

# Generate some traffic to see policies in action
curl http://localhost:8080/api

# Try unauthorized access
kubectl run attacker --image=curlimages/curl --rm -i --tty -- curl backend.demo:8080

echo "Check the Hubble output to see allowed vs denied traffic!"
```

### Security Audit and Compliance

```bash
# Get security policy summary
kubectl get ciliumnetworkpolicies -n demo

# View detailed policy information
kubectl describe ciliumnetworkpolicy default-deny-all -n demo

# Check which pods are affected by policies
cilium endpoint list | grep demo

# View security identity assignments
cilium identity list
```

## Step 10: Key Security Features Demonstrated

### 1. **Zero-Trust by Default**
- **Default Deny**: All communication blocked unless explicitly allowed
- **Identity-Based**: Policies based on service identity, not IP addresses
- **Principle of Least Privilege**: Only allow exactly what's needed

### 2. **Layer 7 Security**
- **HTTP Method Filtering**: Allow only specific HTTP methods
- **Path-Based Rules**: Restrict access to specific API endpoints
- **Protocol Awareness**: Understand and filter application protocols

### 3. **DNS Security**
- **DNS Policy Enforcement**: Control which DNS queries are allowed
- **FQDN Filtering**: Allow/deny based on domain names
- **DNS Monitoring**: See all DNS queries in real-time

### 4. **Encryption by Default**
```bash
# Enable transparent encryption (if supported)
cilium config | grep encryption

# View encrypted connections
hubble observe --namespace demo --type trace | grep -i encrypt
```

### 5. **Multi-Cluster Security**
```bash
# View cluster mesh security status
cilium clustermesh status

# Cross-cluster policies (if enabled)
kubectl get ciliumclusterwidenetworkpolicies
```

## Comparison: Standard K8s vs Cilium Security

### Standard Kubernetes Security:
- **Network Policies**: Basic L3/L4 rules based on IP addresses
- **No Default Security**: Everything allowed by default
- **Limited Observability**: No built-in network monitoring
- **Performance Impact**: iptables-based, scales poorly

### Cilium Security Advantages:
- **Identity-Based**: Policies follow workloads, not IP addresses
- **Zero-Trust Default**: Secure by default, explicit allow model
- **Layer 7 Awareness**: HTTP, gRPC, Kafka protocol filtering
- **Real-time Monitoring**: See security events as they happen
- **eBPF Performance**: Kernel-level enforcement, minimal overhead
- **Encryption**: Transparent network encryption
- **DNS Security**: Control and monitor DNS traffic

```bash
# See the difference in policy effectiveness
echo "📊 Policy Effectiveness Comparison:"
echo "Standard K8s NetworkPolicy: IP-based, L3/L4 only"
echo "Cilium NetworkPolicy: Identity-based, L3-L7, DNS, encryption"
```

## Step 11: Troubleshooting with Hubble and Security Context

### Common Troubleshooting Scenarios

```bash
# 1. Check connectivity issues
hubble observe --verdict DROPPED --namespace demo

# 2. Check DNS resolution
hubble observe --protocol dns --namespace demo

# 3. Check service-to-service communication
hubble observe --from-service demo/frontend --to-service demo/backend

# 4. Check network policy violations
hubble observe --verdict DENIED --namespace demo

# 5. Monitor specific pod traffic
POD_NAME=$(kubectl get pods -n demo -l app=backend -o jsonpath='{.items[0].metadata.name}')
hubble observe --pod demo/$POD_NAME

# 6. Check for performance issues
hubble observe --protocol http --namespace demo --output json | jq '.l7.http.latency'
```

## Step 12: Cleanup

```bash
# Stop port forwarding
pkill -f "kubectl port-forward"
pkill -f "cilium hubble"

# Delete the cluster
kind delete cluster

echo "🧹 Cleanup completed!"
```

## Key Security and Observability Features Demonstrated

### 1. **Real-time Flow Visibility**
- See all network traffic between services
- Identify communication patterns
- Monitor protocols (HTTP, DNS, TCP, etc.)

### 2. **Security Policy Enforcement**
- Visualize network policy effects
- See denied traffic in real-time
- Understand service dependencies

### 3. **Service Map Generation**
- Automatic discovery of service relationships
- Visual representation of traffic flows
- Dependency mapping

### 4. **Performance Monitoring**
- Latency measurements
- Traffic volume analysis
- Error rate tracking

### 5. **Troubleshooting Capabilities**
- Identify connectivity issues
- Debug DNS problems
- Analyze dropped packets

## What Makes This Different from Standard K8s

1. **Identity-Based Security**: Policies based on service identity, not IPs
2. **Deep Packet Inspection**: Protocol-aware observability
3. **Real-time Visibility**: Live network flow monitoring
4. **Zero-Config Observability**: Automatic service discovery
5. **eBPF Performance**: Kernel-level packet processing

The key advantage is having complete visibility into your cluster's network behavior without any application changes or additional instrumentation!
