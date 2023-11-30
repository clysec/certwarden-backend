package dns_checker

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// thresholds to decide if checking succeeded for not.
// propagationRequirement is the portion of functioning dns services that need
// to return the expected record for the check to yield TRUE (e.g. 1 = 100%)
// functioningRequirement is the portion of DNS services that must not fail to
// resolve in order for a check to not produce an Error.
const (
	propagationRequirement = 1.0
	functioningRequirement = 0.5
)

// checkDnsRecord checks if the fqdn has a record of the specified type, set to the specified
// value, on the specified dns resolver. If the record does not exist or exists but the value is
// different, false is returned. If there is an error querying for the record, an error is returned.
func checkDnsRecord(fqdn string, recordValue string, recordType dnsRecordType, r *net.Resolver) (exists bool, err error) {
	var values []string

	// nil check
	if r == nil {
		return false, errors.New("can't check record, resolver is nil")
	}

	// timeout context
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSeconds*time.Second)
	defer cancel()

	// run appropriate query function
	switch recordType {
	// TXT records
	case txtRecord:
		values, err = r.LookupTXT(ctx, fqdn)

	// any other (unsupported)
	default:
		return false, errors.New("unsupported dns record type")
	}

	// error check
	if err != nil {
		// if host wasn't found, this isn't a real error, it actually just means
		// the record does not exist
		dnsErr := new(net.DNSError)
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}

		// any other error, server failed
		return false, err
	}

	// check for desired value
	for i := range values {
		// if value found
		if values[i] == recordValue {
			return true, nil
		}
	}

	// records exist but desired value wasn't found
	return false, nil
}

// checkDnsRecordAllServices sends concurrent dns requests using all configured
// resolvers to check for the existence of the specified record. If the propagation
// requirement is met, TRUE is returned. An Error is returned if the functioning
// requirement is not met.
func (service *Service) checkDnsRecordAllServices(fqdn string, recordValue string, recordType dnsRecordType) (exists bool) {
	// if no resolvers (i.e. configured to skip)
	if service.dnsResolvers == nil {
		// sleep the skip wait and then return true (assume propagated)
		service.logger.Debugf("dns check (%s): skipping and sleeping %d seconds", fqdn, int(service.skipWait.Seconds()))

		// sleep or cancel/error if shutdown is called
		select {
		case <-service.shutdownContext.Done():
			// cancel/error if shutting down
			return false

		case <-time.After(service.skipWait):
			// sleep and retry
		}

		return true
	}

	// use waitgroup for concurrent checking
	var wg sync.WaitGroup
	resolverTotal := len(service.dnsResolvers)

	wg.Add(resolverTotal)
	wgResults := make(chan bool, resolverTotal)
	wgErrors := make(chan error, resolverTotal)

	// for each resolver pair, start a Go Routine
	for i := range service.dnsResolvers {
		go func(i int) {
			defer wg.Done()
			result, e := service.dnsResolvers[i].checkDnsRecord(fqdn, recordValue, recordType)
			wgResults <- result
			wgErrors <- e
		}(i)
	}

	// wait for all queries to finish
	wg.Wait()

	// close channels
	close(wgResults)
	close(wgErrors)

	// make array of all returned errors
	returnedErrs := []error{}
	for err := range wgErrors {
		if err != nil {
			returnedErrs = append(returnedErrs, err)
		}
	}

	// calculate dns resolver failure rate
	errCount := len(returnedErrs)
	errRate := float32(errCount) / float32(resolverTotal)
	service.logger.Debugf("dns check (%s): resolver fail count: %d, resolver fail rate: %.2f, resolver fail threshold: %.2f", fqdn, errCount, errRate, functioningRequirement)

	// if error rate is greater than tolerable, return not propagated
	if errRate > (1 - functioningRequirement) {
		return false
	}

	// error rate was acceptable, check results
	successCount := 0
	for existed := range wgResults {
		if existed {
			successCount++
		}
	}

	// calculate propagation
	propagationRate := float32(successCount) / float32(resolverTotal-errCount)
	service.logger.Debugf("dns check (%s): propagation success count: %d, resolver count: %d, propagation rate: %.2f, propagation requirement: %.2f", fqdn, successCount, resolverTotal, propagationRate, propagationRequirement)

	// return true if rate >= requirement
	return propagationRate >= propagationRequirement
}
