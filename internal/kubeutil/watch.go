/*
Copyright 2023 The cert-manager Authors.

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

package kubeutil

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/go-logr/logr"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type linkedResourceHandler struct {
	cache      cache.Cache
	objType    client.Object
	addToQueue func(q workqueue.TypedRateLimitingInterface[reconcile.Request], req reconcile.Request)

	refField string
	scheme   *runtime.Scheme
	logger   logr.Logger
}

// NewLinkedResourceHandler returns a `handler.EventHandler` that can be
// passed to a `ctrl.Watch` function. Such a handler transforms the watch events
// that originate from the `source.Source` that was passed to `ctrl.Watch`.
// This LinkedResourceHandler transforms a watch event for a watched resource to
// events for all resources that link to this watched resource.
//
//	eg.: resources A1, A2 and A3 all have a spec field that contains the B1 resource
//	name. Now, we watch the B1 resource for changes and translate a watch event for
//	this resource to an event for resource A1, an event for A2 and an event for A3
//
// To achieve this result performantly, we use a cache with an index. This cache
// contains all resources (A1, A2, ...) that reference resources we receive events for.
// We also register an index which is kept up-to-date by the cache when a resource (A1, A2, ...)
// is added, removed or update. This index contains unique "<namespace>/<name>" identifiers
// generated by the provided `toId` function. These identifiers represent what resource
// (B1, B2, ...) the resources in the cache (A1, A2, ...) link to. Lastly, the `addToQueue`
// function can be used to alter the operation that adds an item to the working queue. This
// makes it possible to, instead of adding the event in the queue, post events on a channel.
// The default nil value for `addToQueue` results in just using the `q.Add(req)` function to
// add events to the queue.
func NewLinkedResourceHandler(
	cacheCtx context.Context,
	logger logr.Logger,
	scheme *runtime.Scheme,
	cache cache.Cache,
	objType client.Object,
	toId func(obj client.Object) []string,
	addToQueue func(q workqueue.TypedRateLimitingInterface[reconcile.Request], req reconcile.Request),
) (handler.EventHandler, error) {
	// a random index name prevents collisions with other indexes
	refField := fmt.Sprintf(".x-index.%s", randStringRunes(10))

	if err := SetGroupVersionKind(scheme, objType); err != nil {
		return nil, err
	}

	// the registered index allows us to quickly list cached resources
	// based on the index value which contains the unique identifier
	// for the linked resource that we received an event for
	if err := cache.IndexField(cacheCtx, objType, refField, toId); err != nil {
		return nil, err
	}

	return &linkedResourceHandler{
		logger:     logger,
		scheme:     scheme,
		cache:      cache,
		objType:    objType,
		addToQueue: addToQueue,

		refField: refField,
	}, nil
}

// findObjectsForKind is a handler.MapFunc which returns the namespaced names
// of all the resultingType resources having an reference that matches the
// supplied sourceType.
// Errors are logged (not returned) due to a limitation of the handler.MapFunc
// interface. See
// https://github.com/kubernetes-sigs/controller-runtime/issues/1996
// https://github.com/kubernetes-sigs/controller-runtime/issues/1923
func (r *linkedResourceHandler) findObjectsForKind(ctx context.Context, object client.Object) []reconcile.Request {
	logger := r.logger.WithName("FindObjectsForKind").WithValues(
		"object", client.ObjectKeyFromObject(object),
		"objectType", fmt.Sprintf("%T", object),
	)

	objList, err := NewListObject(r.scheme, r.objType.GetObjectKind().GroupVersionKind())
	if err != nil {
		logger.Error(err, "While creating a List object")
		return nil
	}
	listOps := &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(r.refField, fmt.Sprintf("%s/%s", object.GetNamespace(), object.GetName())),
	}

	if err := r.cache.List(ctx, objList, listOps); err != nil {
		logger.Error(err, "While listing liked resources")
		return nil
	}

	requests := make([]reconcile.Request, 0, apimeta.LenList(objList))
	if err := apimeta.EachListItem(objList, func(object runtime.Object) error {
		clientObj, ok := object.(client.Object)
		if !ok {
			return fmt.Errorf("object %T cannot be converted to client.Object", object)
		}
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(clientObj),
		})
		return nil
	}); err != nil {
		logger.Error(err, "While itterating list")
		return nil
	}

	return requests
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// Based on https://github.com/kubernetes-sigs/controller-runtime/blob/00f2425ce068525e0ff674dba51c3e76ee6ad2da/pkg/handler/enqueue_mapped.go
// Copied to this linkedResourceHandler type such that dependencies can be injected.

var _ handler.EventHandler = &linkedResourceHandler{}

// Create implements EventHandler.
func (e *linkedResourceHandler) Create(ctx context.Context, evt event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	reqs := map[reconcile.Request]struct{}{}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs)
}

// Update implements EventHandler.
func (e *linkedResourceHandler) Update(ctx context.Context, evt event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	reqs := map[reconcile.Request]struct{}{}
	e.mapAndEnqueue(ctx, q, evt.ObjectOld, reqs)
	e.mapAndEnqueue(ctx, q, evt.ObjectNew, reqs)
}

// Delete implements EventHandler.
func (e *linkedResourceHandler) Delete(ctx context.Context, evt event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	reqs := map[reconcile.Request]struct{}{}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs)
}

// Generic implements EventHandler.
func (e *linkedResourceHandler) Generic(ctx context.Context, evt event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	reqs := map[reconcile.Request]struct{}{}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs)
}

func (e *linkedResourceHandler) mapAndEnqueue(ctx context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request], object client.Object, reqs map[reconcile.Request]struct{}) {
	for _, req := range e.findObjectsForKind(ctx, object) {
		_, ok := reqs[req]
		if !ok {
			if e.addToQueue != nil {
				e.addToQueue(q, req)
			} else {
				q.Add(req)
			}

			reqs[req] = struct{}{}
		}
	}
}
