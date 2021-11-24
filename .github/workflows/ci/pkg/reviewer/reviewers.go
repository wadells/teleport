/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package reviewer

import (
	"math/rand"
	"time"

	"github.com/gravitational/teleport/.github/workflows/ci"

	"github.com/gravitational/trace"
)

type Config struct {
	CodeReviewers        map[string]ci.Reviewer
	CodeReviewersOmit    map[string]bool
	DefaultCodeReviewers []string

	DefaultDocsReviewers []string
}

func (c *Config) CheckAndSetDefaults() error {
	if c.CodeReviewers == nil {
		return trace.BadParameter("code reviewers missing")
	}
	if c.CodeReviewersOmit == nil {
		return trace.BadParameter("code reviewers omit missing")
	}
	if c.DefaultCodeReviewers == nil {
		return trace.BadParameter("default code reviewers missing")
	}
	if c.DefaultDocsReviewers == nil {
		return trace.BadParameter("default docs reviewers missing")
	}
	return nil
}

type Reviewers struct {
	c *Config
}

func NewReviewers(c *Config) (*Reviewers, error) {
	rand.Seed(time.Now().UnixNano())

	if err := c.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &Reviewers{
		c: c,
	}, nil
}

func (r *Reviewers) GetDocsReviewers() []string {
	return r.c.DefaultCodeReviewers

}

// GetCodeReviewers returns a list of code reviewers for this author.
func (r *Reviewers) GetCodeReviewers(name string) []string {
	// Get code reviewer sets for this PR author.
	setA, setB := r.GetCodeReviewerSets(name)

	// Randomly select a reviewer from each set and return a pair of reviewers.
	return []string{
		setA[rand.Intn(len(setA))],
		setB[rand.Intn(len(setB))],
	}
}

func (r *Reviewers) GetCodeReviewerSets(name string) ([]string, []string) {
	// External contributors get assigned from the default reviewer set. Default
	// reviewers will triage and re-assign.
	v, ok := r.c.CodeReviewers[name]
	if !ok {
		return r.c.DefaultCodeReviewers, r.c.DefaultCodeReviewers
	}

	switch v.Group {
	// Terminal team does own reviews.
	case "Terminal":
		return r.getReviewerSets(name, v.Group)
	// Core and Database Access does internal team reviews most of the time,
	// however 30% of the time reviews are cross-team.
	case "Database Access", "Core":
		if rand.Intn(10) > 7 {
			return r.getReviewerSets(name, "Core", "Database Access")
		}
		return r.getReviewerSets(name, v.Group)
	// Non-Core, but internal Teleport authors, get assigned default reviews who
	// will re-assign to appropriate reviewers.
	default:
		return r.c.DefaultCodeReviewers, r.c.DefaultCodeReviewers
	}
}

func (r *Reviewers) getReviewerSets(name string, selectGroup ...string) ([]string, []string) {
	var setA []string
	var setB []string

	for k, v := range r.c.CodeReviewers {
		if skipGroup(v.Group, selectGroup) {
			continue
		}
		if _, ok := r.c.CodeReviewersOmit[k]; ok {
			continue
		}
		// Can not review own PR.
		if k == name {
			continue
		}

		if v.Set == "A" {
			setA = append(setA, k)
		} else {
			setB = append(setB, k)
		}
	}

	return setA, setB
}

func skipGroup(group string, selectGroup []string) bool {
	for _, s := range selectGroup {
		if group == s {
			return false
		}
	}
	return true
}
