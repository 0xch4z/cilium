// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
)

func TestServiceSourceRangesForFrontend(t *testing.T) {
	var addr L3n4Addr
	require.NoError(t, addr.ParseFromString("10.0.0.1:3000/TCP"))

	serviceRanges := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	overrideRanges := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	allow := SVCSourceRangesPolicyAllow

	tests := []struct {
		name                 string
		frontendType         SVCType
		frontendSourceRanges FrontendSourceRanges
		wantPolicy           SVCSourceRangesPolicy
		wantSourceRanges     []netip.Prefix
	}{
		{
			name: "matching frontend source ranges and policy override",
			frontendSourceRanges: FrontendSourceRanges{{
				ServicePort:  80,
				Protocol:     TCP,
				SourceRanges: overrideRanges,
				Policy:       &allow,
			}},
			wantPolicy:       SVCSourceRangesPolicyAllow,
			wantSourceRanges: overrideRanges,
		},
		{
			name: "matching frontend source ranges only override",
			frontendSourceRanges: FrontendSourceRanges{{
				ServicePort:  80,
				Protocol:     TCP,
				SourceRanges: overrideRanges,
			}},
			wantPolicy:       SVCSourceRangesPolicyDeny,
			wantSourceRanges: overrideRanges,
		},
		{
			name: "matching empty override",
			frontendSourceRanges: FrontendSourceRanges{{
				ServicePort: 80,
				Protocol:    TCP,
			}},
			wantPolicy: SVCSourceRangesPolicyDeny,
		},
		{
			name: "not matching frontend servicePort",
			frontendSourceRanges: FrontendSourceRanges{{
				ServicePort:  3000,
				Protocol:     TCP,
				SourceRanges: overrideRanges,
				Policy:       &allow,
			}},
			wantPolicy:       SVCSourceRangesPolicyDeny,
			wantSourceRanges: serviceRanges,
		},
		{
			name: "not matching frontend protocol",
			frontendSourceRanges: FrontendSourceRanges{{
				ServicePort:  80,
				Protocol:     UDP,
				SourceRanges: overrideRanges,
				Policy:       &allow,
			}},
			wantPolicy:       SVCSourceRangesPolicyDeny,
			wantSourceRanges: serviceRanges,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frontendType := tt.frontendType
			if frontendType == "" {
				frontendType = SVCTypeLoadBalancer
			}
			svc := &Service{
				Annotations: map[string]string{
					annotation.ServiceSourceRangesPolicy: string(SVCSourceRangesPolicyDeny),
				},
				SourceRanges:         serviceRanges,
				FrontendSourceRanges: tt.frontendSourceRanges,
			}
			frontend := &Frontend{
				FrontendParams: FrontendParams{
					Address:     addr,
					Type:        frontendType,
					ServicePort: 80,
				},
				Service: svc,
			}

			gotPolicy, gotSourceRanges := svc.SourceRangesForFrontend(frontend)
			require.Equal(t, tt.wantPolicy, gotPolicy)
			require.Equal(t, tt.wantSourceRanges, gotSourceRanges)
		})
	}
}
