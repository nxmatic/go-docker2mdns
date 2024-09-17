package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/hashicorp/mdns"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// CustomFormatter is a custom log formatter for logrus
type CustomFormatter struct {
	logrus.TextFormatter
}

// Format formats the log entry to include the file name and line number
func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Get the caller information
	_, file, line, ok := runtime.Caller(8)
	if ok {
		// Trim the file path to only include the file name
		fileParts := strings.Split(file, "/")
		file = fileParts[len(fileParts)-1]
		entry.Message = fmt.Sprintf("%s:%d %s", file, line, entry.Message)
	}
	return f.TextFormatter.Format(entry)
}

type dynamicZone struct {
	sync.RWMutex
	*mdns.Server
	services map[string]*mdns.MDNSService
}

func newDynamicZone() (*dynamicZone, error) {
	dz := dynamicZone{
		services: make(map[string]*mdns.MDNSService),
	}
	// Retrieve the network interface by name
	iface, err := net.InterfaceByName("host0")
	if err != nil {
		fmt.Printf("failed to get interface: %v", err)
	}
	var errMDNS error
	dz.Server, errMDNS = mdns.NewServer(&mdns.Config{Zone: &dz, Iface: iface, LogEmptyResponses: true})
	if errMDNS != nil {
		return nil, errMDNS
	}
	return &dz, nil
}

func (dz *dynamicZone) AddService(instance string, mdns *mdns.MDNSService) error {
	dz.Lock()
	defer dz.Unlock()

	dz.services[instance] = mdns

	return nil
}

func (dz *dynamicZone) RemoveService(instance string) error {
	dz.Lock()
	defer dz.Unlock()

	delete(dz.services, instance)

	return nil
}

func (dz *dynamicZone) Records(q dns.Question) []dns.RR {
	dz.RLock()
	defer dz.RUnlock()

	var records []dns.RR
	for _, service := range dz.services {
		records = append(records, service.Records(q)...)
	}
	return records
}

type dnsRecordType string

const (
	hostRecordType  dnsRecordType = "Host"
	aliasRecordType dnsRecordType = "Alias"
)

type dnsRecord interface {
	addToZone(docker *client.Client, dynamicZone *dynamicZone) ([]string, error)
	removeFromZone(dynamicZone *dynamicZone) error
	getType() dnsRecordType
}

type mdnsProvider interface {
	newMDNSServices(docker *client.Client) (map[string]*mdns.MDNSService, error)
}

type baseRecord struct {
	mdnsProvider
	dnsRecord
	container             types.ContainerJSON
	mdnsServiceByInstance map[string]*mdns.MDNSService
}

func (record *baseRecord) addToZone(docker *client.Client, dynamicZone *dynamicZone) ([]string, error) {
	mdnsServiceByInstance, err := record.newMDNSServices(docker)
	if err != nil {
		return nil, err
	}

	var mdnsInstances []string
	for mdnsInstance, mdnsService := range mdnsServiceByInstance {
		err = errors.Join(err, dynamicZone.AddService(mdnsInstance, mdnsService))
		mdnsInstances = append(mdnsInstances, mdnsInstance)
	}
	record.mdnsServiceByInstance = mdnsServiceByInstance
	return mdnsInstances, err
}

func (record *baseRecord) removeFromZone(dynamicZone *dynamicZone) error {
	for mdnsInstance := range record.mdnsServiceByInstance {
		dynamicZone.RemoveService(mdnsInstance)
	}
	return nil
}

type aliasRecord struct {
	baseRecord
}

type networkDetails struct {
	networkName string
	hostName    string
	hostIP      net.IP
	hostPorts   nat.PortMap
}

func (record *aliasRecord) newMDNSServices(docker *client.Client) (map[string]*mdns.MDNSService, error) {
	networkDetails, err := record.networkDetails(docker)
	if err != nil {
		return nil, err
	}
	if networkDetails == nil {
		return make(map[string]*mdns.MDNSService), nil
	}
	// Initialize a slice to hold the services
	slice := make(map[string]*mdns.MDNSService)
	var wrappedErrors error = nil

	// Publish the hostname
	canonicalName := regexp.MustCompile(`-\d+$`).ReplaceAllString(strings.TrimPrefix(record.container.Name, "/"), "")
	hostInfo := []string{
		fmt.Sprintf("Container Name: %s", record.container.Name),
		fmt.Sprintf("Container ID: %s", record.container.ID),
		fmt.Sprintf("Network Name: %s", networkDetails.networkName),
		fmt.Sprintf("Hostname: %s", networkDetails.hostName),
		fmt.Sprintf("IP Address: %s", networkDetails.hostIP),
	}

	// Publish services for each exposed port
	for port, bindings := range networkDetails.hostPorts {
		if bindings != nil {
			continue
		}
		portInt := port.Int()
		portProto := port.Proto()

		instance := fmt.Sprintf("%s[%s]", canonicalName, port.Port())
		service := fmt.Sprintf("_container._%s", portProto)
		info := append(hostInfo, fmt.Sprintf("Port: %d", portInt))
		mdns, err := mdns.NewMDNSService(instance, service, "local.", networkDetails.hostName, portInt, []net.IP{networkDetails.hostIP}, info)
		if err != nil {
			wrappedErrors = errors.Join(wrappedErrors, err)
			continue
		}
		slice[mdns.Instance] = mdns
	}

	return slice, wrappedErrors
}

func (record *aliasRecord) networkDetails(docker *client.Client) (*networkDetails, error) {
	for networkName, endpointSettings := range record.container.NetworkSettings.Networks {
		// Skip the 'host' network
		if networkName == "host" {
			logrus.Debugf("Skipping 'host' network for container %s", record.container.Name)
			continue
		}

		// Check for aliases ending with .local
		for _, alias := range endpointSettings.Aliases {
			if strings.HasSuffix(alias, ".local") {
				hostIP := net.ParseIP(endpointSettings.IPAddress)
				hostPorts := record.container.NetworkSettings.Ports

				// Return network details if an alias ends with .local
				return &networkDetails{
					hostName:  alias + ".",
					hostIP:    hostIP,
					hostPorts: hostPorts,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no .local alias found for container %s", record.container.Name)
}

func (c *aliasRecord) getType() dnsRecordType {
	return aliasRecordType
}

type containerEntry struct {
	containerId   string
	containerName string
	records       map[dnsRecordType]dnsRecord
}

func newContainerEntry(container types.ContainerJSON) *containerEntry {
	aliasRecord := newAliasRecord(container)

	return &containerEntry{
		containerId:   container.ID,
		containerName: container.Name,
		records: map[dnsRecordType]dnsRecord{
			aliasRecord.getType(): aliasRecord,
		},
	}
}

func newAliasRecord(container types.ContainerJSON) *aliasRecord {
	record := &aliasRecord{
		baseRecord: baseRecord{
			container: container,
		},
	}
	record.mdnsProvider = record
	record.dnsRecord = record
	return record
}

type mdnsProxy struct {
	sync.Mutex
	dynamicZone *dynamicZone
	containers  map[string]*containerEntry
}

func (mdns *mdnsProxy) addToZone(docker *client.Client, container types.ContainerJSON) {
	mdns.Lock()
	defer mdns.Unlock()

	entry := newContainerEntry(container)

	// Register the records in the cache
	mdns.containers[container.ID] = entry

	aliasRecord := entry.records[aliasRecordType].(*aliasRecord)
	aliasInstances, errC := aliasRecord.addToZone(docker, mdns.dynamicZone)
	if errC != nil {
		logrus.Warnf("no CNAME record for container %s: %v", container.Name, errC)
		return
	}
	aliasRecord.printPublishedInstances(aliasInstances)
}

func (record *baseRecord) printPublishedInstances(instances []string) {
	instanceSet := make(map[string]struct{})
	for _, instance := range instances {
		instanceSet[instance] = struct{}{}
	}

	for instance, service := range record.mdnsServiceByInstance {
		if _, exists := instanceSet[instance]; exists {
			logrus.Debugf("SRV Record: Instance=%s, Service=%s, Host=%s, Port=%d",
				instance, service.Service, service.HostName, service.Port)
		}
	}
}

func (mdns *mdnsProxy) removeFromZone(containerID string) {
	mdns.Lock()
	defer mdns.Unlock()
	if entry, ok := mdns.containers[containerID]; ok {
		for recordType, record := range entry.records {
			logrus.Infof("Shutting down %s record for container %s (%s)", recordType, entry.containerName, entry.containerId)
			record.removeFromZone(mdns.dynamicZone)
		}
		delete(mdns.containers, containerID)
	}
}

func newMDNSProxy() *mdnsProxy {
	return &mdnsProxy{
		containers: make(map[string]*containerEntry),
	}
}

func (mdns *mdnsProxy) initialDiscovery(docker *client.Client, endpoint string) error {
	// List all running containers
	containers, err := docker.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return err
	}
	// Create a new dynamic zone
	dz, err := newDynamicZone()
	if err != nil {
		return err
	}
	mdns.dynamicZone = dz

	// Publish the Docker endpoint as an mDNS service
	mdnsService, err := getDockerEndpointAsMDNSService(endpoint)
	if err != nil {
		return err
	}
	mdns.dynamicZone.AddService("docker-host", mdnsService)

	// Inspect each container
	for _, container := range containers {
		containerJSON, err := docker.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			logrus.Errorf("Error inspecting container %s: %v", container.ID, err)
			continue
		}
		mdns.addToZone(docker, containerJSON)
	}
	return nil
}

func (mdns *mdnsProxy) handleContainerEvent(docker *client.Client, event events.Message) {
	if event.Type == "container" {
		containerID := event.Actor.ID
		switch event.Action {
		case "start":
			container, err := docker.ContainerInspect(context.Background(), containerID)
			if err != nil {
				logrus.Errorf("Error inspecting container: %v", err)
				return
			}
			mdns.addToZone(docker, container)
		case "stop":
			mdns.removeFromZone(containerID)
		}
	}
}

func getDockerContextEndpoint() (string, error) {
	cmd := exec.Command("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// getDockerEndpointAsMDNSService publishes the Docker endpoint as an mDNS service
func getDockerEndpointAsMDNSService(endpoint string) (*mdns.MDNSService, error) {
	// Parse the endpoint to extract the host and port
	parts := strings.Split(endpoint, "://")
	if len(parts) != 2 {
		logrus.Errorf("Invalid endpoint format: %s", endpoint)
		return nil, fmt.Errorf("invalid endpoint format: %s", endpoint)
	}
	protocol := parts[0]
	address := parts[1]

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		logrus.Errorf("Error parsing endpoint address: %v", err)
		return nil, fmt.Errorf("error parsing endpoint address: %v", err)
	}

	// Resolve the host to an IP address
	ips, err := net.LookupIP(host)
	if err != nil {
		logrus.Errorf("Error resolving host to IP address: %v", err)
		return nil, fmt.Errorf("error resolving host to IP address: %v", err)
	}
	if len(ips) == 0 {
		logrus.Errorf("No IP addresses found for host: %s", host)
		return nil, fmt.Errorf("no IP addresses found for host: %s", host)
	}
	ip := ips[0] // Use the first IP address

	port := 2375 // Default Docker port, adjust if necessary
	if portStr != "" {
		port, err = net.LookupPort(protocol, portStr)
		if err != nil {
			logrus.Errorf("Error parsing endpoint port: %v", err)
			return nil, fmt.Errorf("error parsing endpoint port: %v", err)
		}
	}

	// Create the mDNS service
	serviceName := "docker-host"
	serviceType := "_docker._tcp"
	info := []string{fmt.Sprintf("DOCKER_HOST=%s", endpoint)}

	service, err := mdns.NewMDNSService(serviceName, serviceType, "", "", port, []net.IP{ip}, info)
	if err != nil {
		logrus.Errorf("Error creating mDNS service: %v", err)
		return nil, fmt.Errorf("error creating mDNS service: %v", err)
	}

	logrus.Infof("mDNS service created: %s.%s at %s:%d", serviceName, serviceType, ip.String(), port)
	return service, nil
}

func main() {
	// Initialize logrus logger with custom formatter
	logrus.SetFormatter(&CustomFormatter{
		TextFormatter: logrus.TextFormatter{
			FullTimestamp: true,
		},
	})
	logrus.SetLevel(logrus.DebugLevel)

	endpoint, err := getDockerContextEndpoint()
	if err != nil {
		logrus.Fatalf("Error retrieving Docker context endpoint: %v", err)
	}

	// Set the DOCKER_HOST environment and create a Docker client
	os.Setenv("DOCKER_HOST", endpoint)
	logrus.Infof("DOCKER_HOST: %s", os.Getenv("DOCKER_HOST"))
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logrus.Fatalf("Error creating Docker client: %v", err)
	}

	// Start the MDNS proxy
	mdnsProxy := newMDNSProxy()
	err = mdnsProxy.initialDiscovery(docker, endpoint)
	if err != nil {
		logrus.Fatalf("Error starting MDNS proxy: %v", err)
		return
	}

	// Start the event listener
	eventsChan, errChan := docker.Events(context.Background(), types.EventsOptions{})
	for {
		select {
		case event := <-eventsChan:
			if event.Type != "" {
				mdnsProxy.handleContainerEvent(docker, event)

			}
		case err := <-errChan:
			if err != nil {
				log.Printf("Error from events channel: %v", err)
			}
		}
	}
}
