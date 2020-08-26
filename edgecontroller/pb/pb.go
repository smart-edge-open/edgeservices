// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

//nolint:lll
//go:generate protoc -I../../schema/pb -I../../../grpc-ecosystem/grpc-gateway -I../../../grpc-ecosystem/grpc-gateway/third_party/googleapis --go_out=plugins=grpc,paths=source_relative:auth ../../schema/pb/auth.proto

//nolint:lll
//go:generate protoc -I../../schema/pb -I../../../grpc-ecosystem/grpc-gateway -I../../../grpc-ecosystem/grpc-gateway/third_party/googleapis --go_out=plugins=grpc,paths=source_relative:ela ../../schema/pb/ela.proto

//nolint:lll
//go:generate protoc -I../../schema/pb -I../../../grpc-ecosystem/grpc-gateway -I../../../grpc-ecosystem/grpc-gateway/third_party/googleapis --go_out=plugins=grpc,paths=source_relative,Mela.proto=github.com/otcshare/edgecontroller/pb/ela:eva ../../schema/pb/eva.proto

package pb
